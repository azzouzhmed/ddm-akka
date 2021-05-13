package de.hpi.ddm.actors;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.LinkedList;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.ActorSelection;
import akka.actor.Props;
import de.hpi.ddm.singletons.KryoPoolSingleton;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class LargeMessageProxy extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "largeMessageProxy";
	public static final int MAX_MSG_LENGTH = 512;	// arbitrary number

	private LinkedList<BytesMessage> pleaseSendMe = new LinkedList<>();
	private LinkedList<BytesMessage> alreadyReceived = new LinkedList<>();

	public static Props props() {
		return Props.create(LargeMessageProxy.class);
	}

	////////////////////
	// Actor Messages //
	////////////////////
	
	@Data @NoArgsConstructor @AllArgsConstructor
	public static class LargeMessage<T> implements Serializable {
		private static final long serialVersionUID = 2940665245810221108L;
		private T message;
		private ActorRef receiver;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class BytesMessage<T> implements Serializable {
		private static final long serialVersionUID = 4057807743872319842L;
		private T bytes;
		private ActorRef sender;
		private ActorRef receiver;
		private boolean lastChunk;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class PullMessage implements Serializable {
		private static final long serialVersionUID = 1029319082390182309L;
		private ActorRef sender;
		private ActorRef receiver;
		private int lastChunk;
	}
	
	/////////////////
	// Actor State //
	/////////////////
	
	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	////////////////////
	// Actor Behavior //
	////////////////////
	
	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(LargeMessage.class, this::handle)
				.match(BytesMessage.class, this::handle)
				.match(PullMessage.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}
	private void handle(PullMessage pull) {
		// just send the next entry, if we're not finished yet
		this.log().error("Pull, size= " + this.pleaseSendMe.size());

		if(this.pleaseSendMe.size() > 0) {
			BytesMessage m = this.pleaseSendMe.removeFirst();
			this.log().error("Pull from " + pull.sender.toString()+" last chunk: "+m.lastChunk);
			pull.sender.tell(m, this.self());
		}
	}
	private void handle(LargeMessage<?> largeMessage) {
		Object message = largeMessage.getMessage();
		ActorRef sender = this.sender();
		ActorRef receiver = largeMessage.getReceiver();
		ActorSelection receiverProxy = this.context().actorSelection(receiver.path().child(DEFAULT_NAME));
		
		// TODO: Implement a protocol that transmits the potentially very large message object.
		// The following code sends the entire message wrapped in a BytesMessage, which will definitely fail in a distributed setting if the message is large!
		// Solution options:
		// a) Split the message into smaller batches of fixed size and send the batches via ...
		//    a.a) self-build send-and-ack protocol (see Master/Worker pull propagation), or
		//    a.b) Akka streaming using the streams build-in backpressure mechanisms.
		// b) Send the entire message via Akka's http client-server component.
		// c) Other ideas ...
		// Hints for splitting:
		// - To split an object, serialize it into a byte array and then send the byte array range-by-range (tip: try "KryoPoolSingleton.get()").
		// - If you serialize a message manually and send it, it will, of course, be serialized again by Akka's message passing subsystem.
		// - But: Good, language-dependent serializers (such as kryo) are aware of byte arrays so that their serialization is very effective w.r.t. serialization time and size of serialized data.
		// receiverProxy.tell(new BytesMessage<>(message, sender, receiver), this.self());

		// serialize large message
		this.log().error("Starting serialization");
		byte[] serialized = KryoPoolSingleton.get().toBytesWithClass(message);
		byte[] range = new byte[LargeMessageProxy.MAX_MSG_LENGTH];

		this.log().error("Splitting "+serialized.length+"  bytes");
		// split serialized data into smaller chunks
		int rangeStart = 0, rangeEnd = 0;
		for (rangeStart = 0; rangeStart < serialized.length; rangeStart += LargeMessageProxy.MAX_MSG_LENGTH) {
			rangeEnd = rangeStart+LargeMessageProxy.MAX_MSG_LENGTH;
			if (rangeEnd > serialized.length) {
				rangeEnd = serialized.length;
			}
			this.log().error(String.format("Added new range: %d - %d (length: %d)", rangeStart, rangeEnd, rangeEnd-rangeStart));

			// extract range
			range = Arrays.copyOfRange(serialized, rangeStart, rangeEnd);
			this.pleaseSendMe.add(new BytesMessage<>(range, sender, receiver, false));
		}
		// mark last chunk
		this.pleaseSendMe.getLast().lastChunk = true;

		// now process the first message
		BytesMessage firstMessage = this.pleaseSendMe.removeFirst();
		receiverProxy.tell(firstMessage, this.self());
	}

	private void handle(BytesMessage<?> message) {
		// TODO: With option a): Store the message, ask for the next chunk and, if all chunks are present, reassemble the message's content, deserialize it and pass it to the receiver.
		// The following code assumes that the transmitted bytes are the original message, which they shouldn't be in your proper implementation ;-)
		// message.getReceiver().tell(message.getBytes(), message.getSender());

		// just store locally
		this.alreadyReceived.addLast(message);
		ActorSelection senderProxy = this.context().actorSelection(message.sender.path().child(DEFAULT_NAME));

		if(message.lastChunk){
			// put all byte arrays back together and then deserialize them
			ByteBuffer buff = ByteBuffer.allocate(this.alreadyReceived.size() * LargeMessageProxy.MAX_MSG_LENGTH);

			for (BytesMessage msg : this.alreadyReceived) {
				byte[] bytes = (byte[]) msg.bytes;
				buff.put(bytes);
			}
			this.log().error("Total reconstructed length: ", buff.array().length);

			// now deserialize
			Object deserialized = KryoPoolSingleton.get().fromBytes(buff.array());

			this.log().error("Received object: " + deserialized+" class "+deserialized.getClass());
			message.getReceiver().tell(deserialized, this.self());
		} else {

			this.log().error("Requesting next chunk");

			senderProxy.tell(new PullMessage(this.self(), message.getSender(), this.alreadyReceived.size()), this.self());
		}
	}
}
