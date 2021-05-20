package de.hpi.ddm.actors;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.cluster.Cluster;
import akka.cluster.ClusterEvent.CurrentClusterState;
import akka.cluster.ClusterEvent.MemberRemoved;
import akka.cluster.ClusterEvent.MemberUp;
import de.hpi.ddm.structures.BloomFilter;
import de.hpi.ddm.systems.MasterSystem;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import akka.cluster.Member;
import akka.cluster.MemberStatus;

public class Worker extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////
	
	public static final String DEFAULT_NAME = "worker";

	public static Props props() {
		return Props.create(Worker.class);
	}

	private int currentCrackAttemptBitMap = 0; // int has 32 bit, we only need 10 for our passwords

	public Worker() {
		this.cluster = Cluster.get(this.context().system());
		this.largeMessageProxy = this.context().actorOf(LargeMessageProxy.props(), LargeMessageProxy.DEFAULT_NAME);
	}
	
	////////////////////
	// Actor Messages //
	////////////////////

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class WelcomeMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private BloomFilter welcomeData;
	}


	@Data @NoArgsConstructor @AllArgsConstructor
	public static class PasswordCrackedMessage implements Serializable {
		private static final long serialVersionUID = 8443040942748609598L;
		private String plainPassword;
		private ActorRef cracker;
		private long time;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class CrackPasswordMessage implements Serializable {
		private static final long serialVersionUID = 8443040942748609598L;
		private String password;
		private String[] hints;
	}

	/////////////////
	// Actor State //
	/////////////////

	private Member masterSystem;
	private final Cluster cluster;
	private final ActorRef largeMessageProxy;
	private long registrationTime;
	private final String ALPHABET = "ABCDEFGHIJK";
	
	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	@Override
	public void preStart() {
		Reaper.watchWithDefaultReaper(this);
		
		this.cluster.subscribe(this.self(), MemberUp.class, MemberRemoved.class);
	}

	@Override
	public void postStop() {
		this.cluster.unsubscribe(this.self());
	}

	////////////////////
	// Actor Behavior //
	////////////////////

	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(CurrentClusterState.class, this::handle)
				.match(MemberUp.class, this::handle)
				.match(MemberRemoved.class, this::handle)
				.match(WelcomeMessage.class, this::handle)
				.match(CrackPasswordMessage.class, this::crackPassword)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}


	protected String getMissingCharFromHint(String hint) {
		String s = null;
		for(char c : ALPHABET.toCharArray()) {
			s = String.valueOf(c);
			if(!hint.contains(s)) {
				return s;
			}
		}
		throw new RuntimeException("No char of "+ALPHABET+" is missing in "+hint);
	}
	// 11 different chars
	// 11 * 10 * 9 * 8 * ... * 2 = 11!
	// HashMap<Hash, Hint>
	// map[key]
	// |Hint| = 10
	// 20*11! =  798 336 000 ~= 798 MB
	private void crackPassword(CrackPasswordMessage message) {
		// Crack hashes
		//this.log().error("CRACKING PASSWORD {} {}", message.password, message.hints[0]);
		long start = System.currentTimeMillis();
		List<String> crackedHashes = new ArrayList<>();
		StringBuilder passwordAlphabet = new StringBuilder();
		int skipChars = 0;

		for(int hashIndex = 0; hashIndex < message.hints.length; hashIndex++) {
			String hash = message.hints[hashIndex];
			//this.log().info("Cracking hash {}", hash);

			// try out all permutations for every char
			boolean foundHash = false;
			while(!foundHash) {
				char c = this.ALPHABET.toCharArray()[hashIndex + skipChars];

				//this.log().info("Working on char {}", c);
				List<String> attempts = new ArrayList<>();
				String currAlphabet = this.ALPHABET.replace(String.valueOf(c), "");
				heapPermutation(currAlphabet.toCharArray(), 10, attempts);
				//	this.log().info("char {} hashIndex {}/{} skipChars {}", c, hashIndex,message.hints.length,skipChars);
				// crack the permutations
				for (String attempt : attempts) {
					if (hash(attempt).equals(hash)) {
							//this.log().error("CRACKED HINT {} {}", attempt, passwordAlphabet.toString());
						//crackedHashes.add(attempt);

						foundHash = true;
						break;
					}
				}
				if(!foundHash) {
					passwordAlphabet.append(c);
					skipChars++;
				}
				if(passwordAlphabet.length() == 2) {
					//this.log().error("Skipping the rest");

					foundHash = true;
					hashIndex = 1000;	// BREAK
				}
			}
		}
		if(passwordAlphabet.length() == 1) {
			passwordAlphabet.append('K');
		}
		//this.log().info("GOT THE PASSWORD ALPHABET {}", passwordAlphabet.toString());

		// prepare first attempt
		this.currentCrackAttemptBitMap = 0;

		// now start the cracking
		final int maxPasswordPermutations = (int) Math.pow(2, HashStoreActor.PASSWORD_LENGTH);
		char[] passwordChars = passwordAlphabet.toString().toCharArray();
		for(int i = 0; i < maxPasswordPermutations; i++) {
			String password = attemptToString(passwordChars);
			if(hash(password).equals(message.password)) {
				//this.log().error("FOUND THE HASH: {}", password);
				this.context().actorSelection("/user/" + Master.DEFAULT_NAME)
						.tell(new PasswordCrackedMessage(password, this.self(), System.currentTimeMillis()-start), this.self());
				return;
			}

			// calculate next state
			this.currentCrackAttemptBitMap++;
		}


	}
	private String attemptToString(char[] alphabet) {
		StringBuilder builder = new StringBuilder();
		for(int i = 0; i < HashStoreActor.PASSWORD_LENGTH; i++) {
			builder.append(alphabet[(this.currentCrackAttemptBitMap >> i) & 1]);
		}
		return builder.toString();
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

	private void register(Member member) {
		if ((this.masterSystem == null) && member.hasRole(MasterSystem.MASTER_ROLE)) {
			this.masterSystem = member;
			
			this.getContext()
				.actorSelection(member.address() + "/user/" + Master.DEFAULT_NAME)
				.tell(new Master.RegistrationMessage(), this.self());
			
			this.registrationTime = System.currentTimeMillis();
		}
	}
	
	private void handle(MemberRemoved message) {
		if (this.masterSystem.equals(message.member()))
			this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());
	}
	
	private void handle(WelcomeMessage message) {
		final long transmissionTime = System.currentTimeMillis() - this.registrationTime;
		this.log().info("WelcomeMessage with " + message.getWelcomeData().getSizeInMB() + " MB data received in " + transmissionTime + " ms.");
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
		}
		catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	// Generating all permutations of an array using Heap's Algorithm
	// https://en.wikipedia.org/wiki/Heap's_algorithm
	// https://www.geeksforgeeks.org/heaps-algorithm-for-generating-permutations/
	private void heapPermutation(char[] a, int size, List<String> l) {
		// If size is 1, store the obtained permutation
		if (size == 1)
			l.add(new String(a));

		for (int i = 0; i < size; i++) {
			heapPermutation(a, size - 1, l);

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