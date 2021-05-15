package de.hpi.ddm.actors;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.cluster.Cluster;
import akka.cluster.ClusterEvent.CurrentClusterState;
import akka.cluster.ClusterEvent.MemberRemoved;
import akka.cluster.ClusterEvent.MemberUp;
import de.hpi.ddm.singletons.HashStoreSingleton;
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
	public static class QueryPasswordHintsMessage implements Serializable {
		private static final long serialVersionUID = 8443040942748609598L;
		private String hashedPassword;
		private String[] hashedHints;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class BuildRainbowTableMessage implements Serializable {
		private static final long serialVersionUID = 8443040942748609598L;
		private char[] permutationAlphabet;
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
				.match(BuildRainbowTableMessage.class, this::buildRainbowTable)
				.match(HashStoreActor.PasswordAlphabetMessage.class, this::crackPassword)
				.match(QueryPasswordHintsMessage.class, this::preparePassword)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}
	private void buildRainbowTable(BuildRainbowTableMessage message) {
		char[] alphabet = message.permutationAlphabet;
		var list = new ArrayList<String>();

		// create permuatations
		heapPermutation(alphabet, alphabet.length, list);

		this.log().info("Total #permutations: {}", list.size());
		this.log().info(list.get(0));
		this.log().info(list.get(list.size()-1));

		// hash all
		HashMap<String, String> map = new HashMap<>();
		list.parallelStream().forEach(permutation -> {
			String hash = hash(permutation);
			map.put(hash, permutation);
		});

		// update store
		this.context().actorSelection("/user/"+HashStoreActor.PROXY_NAME)
			.tell(new HashStoreActor.NewContentMessage(map, this.self()), this.self());
	}

	// 11 different chars
	// 11 * 10 * 9 * 8 * ... * 2 = 11!
	// HashMap<Hash, Hint>
	// map[key]
	// |Hint| = 10
	// 20*11! =  798 336 000 ~= 798 MB
	private void crackPassword(HashStoreActor.PasswordAlphabetMessage message) {
		char[] alphabet = message.getPasswordAlphabet().toCharArray();
		String passwordHash = message.getPassword();

		// prepare first attempt
		this.currentCrackAttemptBitMap = 0;

		// now start the cracking
		final int maxPasswordPermutations = (int) Math.pow(2, HashStoreActor.PASSWORD_LENGTH);
		for(int i = 0; i < maxPasswordPermutations; i++) {
			String password = attemptToString(alphabet);
			if(hash(password) == passwordHash) {
				this.log().error("FOUND THE HASH: {}", password);
				this.context().actorSelection("/user/"+Master.DEFAULT_NAME)
						.tell(new Master.PasswordCrackedMessage(password, passwordHash), this.self());
				return;
			}

			// calculate next state
			this.currentCrackAttemptBitMap++;
		}
		this.log().error("Password with hash {} could not be cracked!", passwordHash);
	}
	private String attemptToString(char[] alphabet) {
		StringBuilder builder = new StringBuilder();
		for(int i = 0; i < HashStoreActor.PASSWORD_LENGTH; i++) {
			builder.append(alphabet[(this.currentCrackAttemptBitMap >> i) & 1]);
		}
		return builder.toString();
	}

	// queries the alphabet
	private void preparePassword(QueryPasswordHintsMessage message) {
		// when completed, this will call crackHint
		this.context().actorSelection("/user/" + HashStoreActor.DEFAULT_NAME)
				.tell(new HashStoreActor.GetAlphabetMessage(message.getHashedHints(), message.getHashedPassword(), this.self()), this.self());
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