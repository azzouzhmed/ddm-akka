package de.hpi.ddm.actors;

import akka.actor.*;
import akka.cluster.Cluster;
import akka.cluster.ClusterEvent.CurrentClusterState;
import akka.cluster.ClusterEvent.MemberRemoved;
import akka.cluster.ClusterEvent.MemberUp;
import akka.cluster.Member;
import akka.cluster.MemberStatus;
import de.hpi.ddm.structures.BloomFilter;
import de.hpi.ddm.structures.PasswordEntry;
import de.hpi.ddm.systems.MasterSystem;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

public class Worker extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "worker";
	private final Map<String, String> hashValueAlphabetMap;
	private final Queue<PasswordEntry> passwordsToCrack;
	private final Set<String> alphabets;

	public static Props props() {
		return Props.create(Worker.class);
	}

	public Worker() {
		this.cluster = Cluster.get(this.context().system());
		this.largeMessageProxy = this.context().actorOf(LargeMessageProxy.props(), LargeMessageProxy.DEFAULT_NAME);
		hashValueAlphabetMap = new HashMap<>();
		this.passwordsToCrack = new ArrayDeque<>();
		alphabets = new HashSet<>();
	}

	////////////////////
	// Actor Messages //
	////////////////////

	@Override
	public void preStart() {
		Reaper.watchWithDefaultReaper(this);

		this.cluster.subscribe(this.self(), MemberUp.class, MemberRemoved.class);
	}

	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(CurrentClusterState.class, this::handle)
				.match(MemberUp.class, this::handle)
				.match(MemberRemoved.class, this::handle)
				.match(WelcomeMessage.class, this::handle)
				.match(HashAlphabetMessage.class, this::hashAlphabet)
				.match(CrackPasswordMessage.class, this::crackPassword)
				.match(HintHashValueRequest.class, this::lookUp)
				.match(HintHashValueResponse.class, this::handleHintResponse)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	private void handleHintResponse(HintHashValueResponse hintHashValueResponse) {
		var passwordEntry = this.passwordsToCrack.poll();
		if (hintHashValueResponse.getValue() != null) {
			passwordEntry.getHashedHints().remove(hintHashValueResponse.getHashedValue());
			passwordEntry.getHints().add(hintHashValueResponse.getValue());
		}
		this.crackPassword(new CrackPasswordMessage(passwordEntry));
	}

	private void lookUp(HintHashValueRequest hintHashValueRequest) {
		if (hashValueAlphabetMap.containsKey(hintHashValueRequest.hashedValue)) {
			hintHashValueRequest.getAskingWorkerAddress()
					.tell(new HintHashValueResponse(
									hintHashValueRequest.hashedValue,
									hashValueAlphabetMap.get(hintHashValueRequest.hashedValue),
									this.self().path()),
							this.self());
		}
	}

	private void crackPassword(CrackPasswordMessage crackPasswordMessage) {
		var start = System.currentTimeMillis();
		passwordsToCrack.add(crackPasswordMessage.getPasswordEntry());
		while (!crackPasswordMessage.getPasswordEntry().getHashedHints().isEmpty()) {
			if (crackHint(crackPasswordMessage)) break;
		}
		if (crackPasswordMessage.getPasswordEntry().getHashedHints().isEmpty()) {
			log().info("ALL HINTS OF #{} {} ARE CRACKED, TOTAL TIME {} ms",
					crackPasswordMessage.getPasswordEntry().getId(),
					crackPasswordMessage.getPasswordEntry().getName(),
					System.currentTimeMillis() - start);
			crackPassword(passwordsToCrack.poll(), start);
		}
	}

	private boolean crackHint(CrackPasswordMessage crackPasswordMessage) {
		var hashedHint = crackPasswordMessage.getPasswordEntry().getHashedHints().peek();
		if (hashValueAlphabetMap.containsKey(hashedHint)) {
			crackPasswordMessage.getPasswordEntry().getHashedHints().remove(hashedHint);
			crackPasswordMessage.getPasswordEntry().getHints().add(hashValueAlphabetMap.get(hashedHint));
		} else {
			this.getContext()
					.actorSelection(this.masterSystem.address() + "/user/" + Master.DEFAULT_NAME)
					.tell(new HintHashValueRequest(hashedHint, getSelf()), this.self());
			return true;
		}
		return false;
	}

	private void crackPassword(PasswordEntry passwordEntry, long start) {
		for (var passwordAlphabet : alphabets) {
			String hints = passwordAlphabet;
			for (var hint : passwordEntry.getHints()) {
				var passwordAlphabetCharacterSet = passwordAlphabet.chars().mapToObj(c -> (char) c).collect(Collectors.toSet());
				var hintCharacters = hint.chars().mapToObj(c -> (char) c).collect(Collectors.toSet());
				passwordAlphabetCharacterSet.removeAll(hintCharacters);
				for (var character : passwordAlphabetCharacterSet) {
					if (hints.contains(character.toString())) {
						hints = hints.replaceAll(character.toString(), "");
					}
				}
			}
			if (hints.length() >= 2) {
				log().info("START CRACKING PASSWORD OF USER #{} {}", passwordEntry.getId(), passwordEntry.getName());
				final int maxPasswordPermutations = (int) Math.pow(2, passwordEntry.getPasswordLength());
				int currentCrackAttemptBitMap = 0;
				for (int i = 0; i < maxPasswordPermutations; i++) {
					String password = attemptToString(hints.toCharArray(), passwordEntry.getPasswordLength(), currentCrackAttemptBitMap);
					var hashedValue = hash(password);
					if (hashedValue.equals(passwordEntry.getHashedPassword())) {
						passwordEntry.setPlainPassword(password);
						log().info("PASSWORD CRACKED FOR USER #{} {}: {}, TOTAL TIME {} ms",
								passwordEntry.getId(), passwordEntry.getName(), password, System.currentTimeMillis() - start);
						this.getContext()
								.actorSelection(this.masterSystem.address() + "/user/" + Master.DEFAULT_NAME)
								.tell(new CrackPasswordDoneMessage(passwordEntry), this.self());
						return;
					}

					// calculate next state
					currentCrackAttemptBitMap++;
				}
			}
		}
	}

	/////////////////
	// Actor State //
	/////////////////

	private Member masterSystem;
	private final Cluster cluster;
	private final ActorRef largeMessageProxy;
	private long registrationTime;

	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	private String attemptToString(char[] alphabet, int passwordLength, int currentCrackAttemptBitMap) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < passwordLength; i++) {
			builder.append(alphabet[(currentCrackAttemptBitMap >> i) & 1]);
		}
		return builder.toString();
	}

	@Override
	public void postStop() {
		this.cluster.unsubscribe(this.self());
	}

	////////////////////
	// Actor Behavior //
	////////////////////

	private void hashAlphabet(HashAlphabetMessage alphabetMessage) {
		var start = System.currentTimeMillis();
		alphabets.add(alphabetMessage.getPasswordAlphabet());
		this.log().info("HASHING ALPHABET: {}", alphabetMessage.getPasswordAlphabet());

		var permutations = new ArrayList<String>();
		heapPermutation(alphabetMessage.getPasswordAlphabet().toCharArray(), alphabetMessage.getPasswordAlphabet().length(), permutations, alphabetMessage.getPasswordSuffix());


		this.log().info("ALPHABET: {}", alphabetMessage.getPasswordAlphabet());
		for (var permutation : permutations) {
			var hashed = hash(permutation);
			hashValueAlphabetMap.put(hashed, permutation);
		}
		log().info("HASHING FINISHED - TOTAL TIME {} ms", System.currentTimeMillis() - start);
		this.getContext()
				.actorSelection(this.masterSystem.address() + "/user/" + Master.DEFAULT_NAME)
				.tell(new HashAlphabetDoneMessage(alphabetMessage.passwordAlphabet), this.self());
	}

	private void register(Member member) {
		if ((this.masterSystem == null) && member.hasRole(MasterSystem.MASTER_ROLE)) {
			this.masterSystem = member;

			this.getContext()
					.actorSelection(member.address() + "/user/" + Master.DEFAULT_NAME)
					.tell(new Master.RegistrationMessage(), this.self());

			this.registrationTime = System.currentTimeMillis();
		}
	}

	private String hash(String characters) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashedBytes = digest.digest(String.valueOf(characters).getBytes("UTF-8"));

			StringBuffer stringBuffer = new StringBuffer();
			for (int i = 0; i < hashedBytes.length; i++) {
				stringBuffer.append(Integer.toString((hashedBytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			return stringBuffer.toString();
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public static class WelcomeMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private BloomFilter welcomeData;
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public static class HashAlphabetMessage implements Serializable {
		private static final long serialVersionUID = 1L;
		private String passwordAlphabet;
		private String passwordSuffix;
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public static class CrackPasswordMessage implements Serializable {
		private static final long serialVersionUID = 1L;
		private PasswordEntry passwordEntry;
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public static class CrackPasswordDoneMessage implements Serializable {
		private static final long serialVersionUID = 1L;
		private PasswordEntry passwordEntry;
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public static class HashAlphabetDoneMessage implements Serializable {
		private static final long serialVersionUID = 1L;
		private String passwordAlphabet;
	}

	private void handle(CurrentClusterState message) {
		message.getMembers().forEach(member -> {
			if (member.status().equals(MemberStatus.up()))
				this.register(member);
		});
	}

	private void handle(MemberUp message) {
		this.register(message.member());
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public static class HintHashValueRequest implements Serializable {
		private static final long serialVersionUID = 1L;
		private String hashedValue;
		private ActorRef askingWorkerAddress;
	}

	private void handle(MemberRemoved message) {
		if (this.masterSystem.equals(message.member()))
			this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());
	}

	private void handle(WelcomeMessage message) {
		final long transmissionTime = System.currentTimeMillis() - this.registrationTime;
		this.log().info("WelcomeMessage with " + message.getWelcomeData().getSizeInMB() + " MB data received in " + transmissionTime + " ms.");
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public static class HintHashValueResponse implements Serializable {
		private static final long serialVersionUID = 1L;
		private String hashedValue;
		private String value;
		private ActorPath respondingWokerAddress;
	}


	// Generating all permutations of an array using Heap's Algorithm
	// https://en.wikipedia.org/wiki/Heap's_algorithm
	// https://www.geeksforgeeks.org/heaps-algorithm-for-generating-permutations/
	private void heapPermutation(char[] a, int size, List<String> l, String prefix) {
		// If size is 1, store the obtained permutation
		if (size == 1)
			l.add(prefix+new String(a));

		for (int i = 0; i < size; i++) {
			heapPermutation(a, size - 1, l, prefix);

			// If size is odd, swap first and last element
			if (size % 2 == 1) {
				char temp = a[0];
				a[0] = a[size - 1];
				a[size - 1] = temp;
			}

			// If size is even, swap i-th and last element
			else {
				char temp = a[i];
				a[i] = a[size - 1];
				a[size - 1] = temp;
			}
		}
	}
}
