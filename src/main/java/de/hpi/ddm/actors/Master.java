package de.hpi.ddm.actors;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import akka.actor.*;
import de.hpi.ddm.structures.BloomFilter;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class Master extends AbstractLoggingActor {
	/*
		README:
		the current flow is as follows:
		1. the workers build a rainbow table and send them to the HashStoreActor
		2. the workers look up the hints to get the password alphabet and crack it

		1. (Master) -> BuildRainbowTableMessage -> (Worker) -> NewContentMessage -> (HashStoreActor) -> NewContentAddedMessage -> (Master) (repeat)
		2. (Master) -> QueryPasswordHintsMessage -> (Worker) -> GetAlphabetMessage -> (HashStoreActor) -> PasswordAlphabetMessage -> (Worker) -> PasswordCrackedMessage -> (Master) (repeat)

		Currently, the master is not capable of starting/repeating those processes

	 */
	////////////////////////
	// Actor Construction //
	////////////////////////
	
	public static final String DEFAULT_NAME = "master";

	public static Props props(final ActorRef reader, final ActorRef collector, final BloomFilter welcomeData) {
		return Props.create(Master.class, () -> new Master(reader, collector, welcomeData));
	}

	public Master(final ActorRef reader, final ActorRef collector, final BloomFilter welcomeData) {
		this.reader = reader;
		this.collector = collector;
		this.workers = new ArrayList<>();
		this.largeMessageProxy = this.context().actorOf(LargeMessageProxy.props(), LargeMessageProxy.DEFAULT_NAME);
		this.welcomeData = welcomeData;
	}

	////////////////////
	// Actor Messages //
	////////////////////

	@Data
	public static class StartMessage implements Serializable {
		private static final long serialVersionUID = -50374816448627600L;
	}
	
	@Data @NoArgsConstructor @AllArgsConstructor
	public static class BatchMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private List<String[]> lines;
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
	private static int completedBuilders = 0;
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

	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(StartMessage.class, this::handle)
				.match(BatchMessage.class, this::handle)
				.match(Terminated.class, this::handle)
				.match(RegistrationMessage.class, this::handle)
				.match(Worker.PasswordCrackedMessage.class, this::collect)
				// TODO: Add further messages here to share work between Master and Worker actors
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	protected int passwordCounter = 0;
	protected void collect(Worker.PasswordCrackedMessage message) {
		// here we decide to start additional builders
		this.log().info("Worker {} cracked a password ({}): {} in {} ms", message.getCracker(), passwordCounter++, message.getPlainPassword(), message.getTime());		if(todo.size() > 0) {
			message.getCracker().tell(todo.remove(0), this.self());
		}
		if(todo.size() < 10) {
			// fetch news
			this.reader.tell(new Reader.ReadMessage(), this.self());
		}
		this.collector.tell(new Collector.CollectMessage(message.getPlainPassword()), this.self());
	}

	protected void handle(StartMessage message) {
		this.startTime = System.currentTimeMillis();

		// first we start building the rainbow table


		this.reader.tell(new Reader.ReadMessage(), this.self());
	}

	protected List<Worker.CrackPasswordMessage> todo = new ArrayList<>();
	protected boolean started = false;
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
		if (message.getLines().isEmpty()) {
			this.terminate();
			return;
		}
		
		// TODO: Process the lines with the help of the worker actors
		for (String[] line : message.getLines()){
			String password = line[4];
			String[] hints = Arrays.copyOfRange(line, 5, line.length);
			todo.add(new Worker.CrackPasswordMessage(password, hints));
		}
		if(!started) {
			// for each worker work on todo
			for (ActorRef worker : this.workers) {
				if (todo.size() > 0) {
					worker.tell(todo.remove(0), this.self());
				}
			}
			started = true;
		}
		// TODO: Send (partial) results to the Collector
		//this.collector.tell(new Collector.CollectMessage("If I had results, this would be one."), this.self());
		
		// TODO: Fetch further lines from the Reader

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
		
		// TODO: Assign some work to registering workers. Note that the processing of the global task might have already started.
	}
	
	protected void handle(Terminated message) {
		this.context().unwatch(message.getActor());
		this.workers.remove(message.getActor());
		this.log().info("Unregistered {}", message.getActor());
	}

}
