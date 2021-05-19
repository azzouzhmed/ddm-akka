package de.hpi.ddm.actors;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.Props;
import akka.cluster.Cluster;
import akka.cluster.ClusterEvent;
import de.hpi.ddm.singletons.HashStoreSingleton;
import de.hpi.ddm.structures.BloomFilter;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;

public class HashStoreActor extends AbstractLoggingActor {

    public static final String DEFAULT_NAME = "HStore";
    public static final String PROXY_NAME = "HStoreProxy";
    public static final String ALPHABET = "ABCDEFGHIJK";
    public static int ALPHABET_LENGTH = ALPHABET.length();
    public static final int PASSWORD_LENGTH = 10;

    public static Props props() {
        return Props.create(HashStoreActor.class);
    }

    private final Cluster cluster;
    private final ActorRef largeMessageProxy;
    public HashStoreActor() {
        this.cluster = Cluster.get(this.context().system());
        this.largeMessageProxy = this.context().actorOf(LargeMessageProxy.props(), PROXY_NAME);
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class NewContentMessage implements Serializable {
        private static final long serialVersionUID = 8343040942748609598L;
        private HashMap<String, String> hashed;
        private ActorRef builder;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class NewContentAddedMessage implements Serializable {
        private static final long serialVersionUID = 8343040942748609598L;
        private ActorRef builder;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class GetAlphabetMessage implements Serializable {
        private static final long serialVersionUID = 8343040942748609598L;
        private String[] hashedHints;
        private String password;
        private ActorRef requester;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PasswordAlphabetMessage implements Serializable {
        private static final long serialVersionUID = 8343040942748609598L;
        private String passwordAlphabet;
        private String password;
    }

    @Override
    public void preStart() {
        Reaper.watchWithDefaultReaper(this);

        this.cluster.subscribe(this.self(), ClusterEvent.MemberUp.class, ClusterEvent.MemberRemoved.class);
    }

    @Override
    public void postStop() {
        this.cluster.unsubscribe(this.self());
    }

    @Override
    public Receive createReceive() {
        return receiveBuilder()
                .match(NewContentMessage.class, this::newContent)
                .match(GetAlphabetMessage.class, this::replyWithPasswordAlphabet)
                .build();
    }

    protected void newContent(NewContentMessage message) {
        HashMap<String, String> content = message.hashed;
        content.putAll(content);
        // inform the master
        this.context().actorSelection("/user/"+Master.DEFAULT_NAME)
                        .tell(new NewContentAddedMessage(message.builder), this.self());
            }

            protected void replyWithPasswordAlphabet(GetAlphabetMessage message) {
                // look up hash
                var alphabets = new ArrayList<String>();

                for(String hash : message.hashedHints) {
                    alphabets.add(getMissingCharFromHint(hash));
                }

                // Now get chars which do not exist
                var opposite = ALPHABET.chars().filter(d -> !alphabets.contains(d))
                        .collect(StringBuilder::new,
                            StringBuilder::appendCodePoint, StringBuilder::append)
                        .toString();
                message.requester.tell(new PasswordAlphabetMessage(opposite, message.password), this.self());
            }

            protected String getMissingCharFromHint(String hint) {
                for(char c : ALPHABET.toCharArray()) {
                    if(!hint.contains(String.valueOf(c))) {
                        return String.valueOf(c);
                    }
                }
                throw new RuntimeException("No char of "+ALPHABET+" is missing in "+hint);
            }
}
