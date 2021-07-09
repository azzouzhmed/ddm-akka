package de.hpi.ddm.actors;

import akka.actor.*;
import de.hpi.ddm.structures.BloomFilter;
import de.hpi.ddm.structures.PasswordEntry;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Master extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "master";

	private final Queue<PasswordEntry> dataQueue;
	private final Queue<Worker.HashAlphabetMessage> hashQueue;
	private final Set<String> crackedPasswords;

	private boolean hashesAlreadyGenerated;

	public static Props props(final ActorRef reader, final ActorRef collector, final BloomFilter welcomeData) {
		return Props.create(Master.class, () -> new Master(reader, collector, welcomeData));
	}

	private final Queue<ActorRef> idleWorkers;

	////////////////////
	// Actor Messages //
	////////////////////

	@Data
	public static class StartMessage implements Serializable {
		private static final long serialVersionUID = -50374816448627600L;
	}

	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(StartMessage.class, this::handle)
				.match(BatchMessage.class, this::handle)
				.match(Terminated.class, this::handle)
				.match(RegistrationMessage.class, this::handle)
				.match(Worker.HashAlphabetDoneMessage.class, this::handle)
				.match(Worker.HintHashValueRequest.class, this::handle)
				.match(Worker.CrackPasswordDoneMessage.class, this::handle)
				// TODO: Add further messages here to share work between Master and Worker actors
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	@Data
	public static class RegistrationMessage implements Serializable {
		private static final long serialVersionUID = 3303081601659723997L;
	}

	/////////////////
	// Actor State //
	/////////////////

	private final ActorRef reader;
	private final ActorRef collector;
	private final List<ActorRef> workers;
	private final ActorRef largeMessageProxy;
	private final BloomFilter welcomeData;

	public Master(final ActorRef reader, final ActorRef collector, final BloomFilter welcomeData) {
		this.reader = reader;
		this.collector = collector;
		this.workers = new ArrayList<>();
		this.largeMessageProxy = this.context().actorOf(LargeMessageProxy.props(), LargeMessageProxy.DEFAULT_NAME);
		this.welcomeData = welcomeData;
		hashQueue = new ArrayDeque<>();
		dataQueue = new ArrayDeque<>();
		crackedPasswords = new HashSet<>();
		idleWorkers = new ArrayDeque<>();
	}

	private long startTime;

	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	@Override
	public void preStart() {
		Reaper.watchWithDefaultReaper(this);
	}

	////////////////////
	// Actor Behavior //
	////////////////////

	private void handle(Worker.CrackPasswordDoneMessage crackPasswordDoneMessage) {
		this.crackedPasswords.add(crackPasswordDoneMessage.getPasswordEntry().getPlainPassword());
		if (!dataQueue.isEmpty()) {
			log().info("#{} PASSWORD STILL HAS TO BE CRACKED", dataQueue.size());
			this.sender().tell(new Worker.CrackPasswordMessage(dataQueue.poll()), this.self());
		} else {
			this.reader.tell(new Reader.ReadMessage(), this.self());
			idleWorkers.add(sender());
			log().info("NUMBER OF IDLE WORKERS: {}", idleWorkers.size());
			if (idleWorkers.size() == workers.size()) {
				log().info("ALL PASSWORD ARE CRACKED, TOTAL NUMBER: {}", crackedPasswords.size());
				crackedPasswords.forEach(password -> this.collector.tell(new Collector.CollectMessage(password), this.self()));
				this.terminate();
			}
		}
	}

	private void handle(Worker.HintHashValueRequest hintHashValueRequest) {
		for (var w : workers) {
			if (!w.path().equals(hintHashValueRequest.getAskingWorkerAddress())) {
				w.tell(hintHashValueRequest, this.self());
			}
		}
	}

	private void handle(Worker.HashAlphabetDoneMessage hashAlphabetDoneMessage) {
		if (!hashQueue.isEmpty()) {
			this.log().info("{} hahes remain", hashQueue.size());
			this.sender().tell(hashQueue.poll(), this.self());
		} else {
			this.log().info("HASHING DONE, CHECK FOR NEW DATA AND START CRACKING");
			log().info("NUMBER OF IDLE WORKERS: {}", idleWorkers.size());
			this.reader.tell(new Reader.ReadMessage(), this.self());
			idleWorkers.add(sender());
			if (idleWorkers.size() == workers.size()) {
				if (!dataQueue.isEmpty()) {
					while (!idleWorkers.isEmpty()) {
						idleWorkers.poll().tell(new Worker.CrackPasswordMessage(dataQueue.poll()), this.self());
					}
				}
			}
		}
	}

	protected void handle(BatchMessage message) {

		// TODO: This is where the task begins:
		// - The Master received the first batch of input records.
		// - To receive the next batch, we need to send another ReadMessage to the reader.
		// - If the received BatchMessage is empty, we have seen all data for this task.
		// - We need a clever protocol that forms sub-tasks from the seen records, distributes the tasks to the known workers and manages the results.
		//   -> Additional messages, maybe additional actors, code that solves the subtasks, ...
		//   -> The code in this handle function needs to be re-written.
		// - Once the entire processing is done, this.terminate() needs to be called.

		// Info: Why is the input file read in batches?
		// a) Latency hiding: The Reader is implemented such that it reads the next batch of data from disk while at the same time the requester of the current batch processes this batch.
		// b) Memory reduction: If the batches are processed sequentially, the memory consumption can be kept constant; if the entire input is read into main memory, the memory consumption scales at least linearly with the input size.
		// - It is your choice, how and if you want to make use of the batched inputs. Simply aggregate all batches in the Master and start the processing afterwards, if you wish.

		// TODO: Stop fetching lines from the Reader once an empty BatchMessage was received; we have seen all data then
		if (message.getLines().isEmpty() && dataQueue.isEmpty() && hashQueue.isEmpty()) {
			this.terminate();
			return;
		}



		log().info("RECEIVED SOME DATA! NUMBER OF LINE #{}", message.getLines().size());
		var passwordEntries = message.getLines().stream().map(line -> {
			var hashedHints = new ArrayDeque<>(Arrays.asList(line).subList(5, line.length));
			return new PasswordEntry(Integer.parseInt(line[0]),
					line[1],
					line[2],
					Integer.parseInt(line[3]),
					line[4],
					"",
					hashedHints,
					new ArrayList<>());
		}).collect(Collectors.toList());

		var distinctSet = new HashSet<>(dataQueue);
		distinctSet.addAll(passwordEntries);
		dataQueue.clear();
		dataQueue.addAll(distinctSet);


		if (!this.workers.isEmpty() && !hashesAlreadyGenerated) {
			// only called once

			// fills hash queue
			prepareHashing(message);


			for (var w : workers) {
				w.tell(hashQueue.poll(), this.self());
			}
			hashesAlreadyGenerated = true;
		}
	}

	protected void handle(StartMessage message) {
		this.startTime = System.currentTimeMillis();

		this.reader.tell(new Reader.ReadMessage(), this.self());
	}

	private List<Character> prepareHashing(BatchMessage message) {
		//get all password characters
		var passwordAlphabetList = message.getLines()
				.stream()
				.map(line -> line[2])
				.distinct()
				.collect(Collectors.toList());

		var passwordAlphabetCharacters = passwordAlphabetList.stream()
				.map(pwd -> pwd.chars().mapToObj(c -> (char) c))
				.flatMap(Stream::distinct)
				.collect(Collectors.toList());

		List<String> allprefixes = getAllPasswordSuffixes(passwordAlphabetCharacters);

		for (var c : passwordAlphabetCharacters) {
			var prefixes = allprefixes.stream().filter(s -> !s.contains(c.toString())).collect(Collectors.toList());
			for (var passwordAlphabet : passwordAlphabetList) {
				var originalAlphabet = passwordAlphabet.replace(c.toString(), "");



				prefixes.stream().forEach(prefix -> {
					var cleanAlphabet = originalAlphabet;

					// remove prefixes
					for (var prefixChar : prefix.toCharArray()) {
						cleanAlphabet = cleanAlphabet.replace(String.valueOf(prefixChar), "");
					}

					// add each
					hashQueue.add(new Worker.HashAlphabetMessage(cleanAlphabet, prefix));
				});
			}
		}
		return passwordAlphabetCharacters;
	}

	// Liste aller möglichen kombinationen aus 2 chars aus dem passwort alphabet
	private List<String> getAllPasswordSuffixes(List<Character> alph) {
		List<String> r = new ArrayList<>();
		int alength = alph.size();

		for (int first = 0; first < alength; first++) {
			for(int sec = 0; sec  < alength; sec++) {
				if(first == sec) {
					r.add(String.valueOf(alph.get(first)));
				}
			}
		}

		return r;
	}

	protected void terminate() {
		this.collector.tell(new Collector.PrintMessage(), this.self());

		this.reader.tell(PoisonPill.getInstance(), ActorRef.noSender());
		this.collector.tell(PoisonPill.getInstance(), ActorRef.noSender());

		for (ActorRef worker : this.workers) {
			this.context().unwatch(worker);
			worker.tell(PoisonPill.getInstance(), ActorRef.noSender());
		}

		this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());

		long executionTime = System.currentTimeMillis() - this.startTime;
		this.log().info("Algorithm finished in {} ms", executionTime);
	}

	protected void handle(RegistrationMessage message) {
		this.context().watch(this.sender());
		this.workers.add(this.sender());
		this.log().info("Registered {}", this.sender());

		this.largeMessageProxy.tell(new LargeMessageProxy.LargeMessage<>(new Worker.WelcomeMessage(this.welcomeData), this.sender()), this.self());
		if (!hashQueue.isEmpty()) {
			this.sender().tell(hashQueue.poll(), this.self());
		}
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public static class BatchMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private List<String[]> lines;
	}

	protected void handle(Terminated message) {
		this.context().unwatch(message.getActor());
		this.workers.remove(message.getActor());
		this.log().info("Unregistered {}", message.getActor());
	}
}
