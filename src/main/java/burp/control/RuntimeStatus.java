package burp.control;

/**
 * What the Go side reports it is actually doing, as opposed to what the settings say it should be.
 * <p>
 * ADR-0001 section 3 is emphatic that Java must not infer this. Whether a listener is up, and on
 * which address, is owned by Go; guessing it from the configured value or from whether a thread is
 * still alive is how "saved" comes to mean "in effect" when it does not — most damagingly for the
 * spoof listener, where believing a new address is live sends every request to a port nothing is
 * bound to.
 * <p>
 * Kept entirely separate from {@link burp.TransportConfig}: this is a read-only status channel, and
 * folding it into the per-request config would change a contract two languages match by field name.
 */
public record RuntimeStatus(
        Listener spoof,
        Listener intercept,
        /**
         * The Burp proxy endpoint the Go side is actually forwarding intercepted traffic to.
         * <p>
         * This is not the same thing as the interface Burp's own proxy listener is bound to. The
         * Montoya API does not expose that, so it must be reported as unavailable rather than
         * assumed to be {@code 127.0.0.1}: assuming it is what makes a port pre-check claim to have
         * ruled out a conflict it cannot see.
         */
        String burpUpstreamEndpoint,
        String burpUpstreamError) {

    public enum State {
        /** Asked to start; the bind has not resolved yet. */
        STARTING,
        RUNNING,
        STOPPED,
        /** Tried and failed. {@link Listener#lastError} says why. */
        FAILED
    }

    /**
     * @param actualAddress where it is really bound, or null when it is not bound at all. Never the
     *                      configured value standing in for the real one.
     */
    public record Listener(State state, String actualAddress, String lastError) {
        public static Listener stopped() {
            return new Listener(State.STOPPED, null, null);
        }

        public boolean running() {
            return state == State.RUNNING;
        }
    }

    public static RuntimeStatus unknown() {
        return new RuntimeStatus(Listener.stopped(), Listener.stopped(), null, null);
    }

    /**
     * @return every address the Go side currently holds, for the MCP port pre-check.
     */
    public java.util.List<String> boundAddresses() {
        var out = new java.util.ArrayList<String>(2);
        if (spoof != null && spoof.actualAddress() != null) out.add(spoof.actualAddress());
        if (intercept != null && intercept.actualAddress() != null) out.add(intercept.actualAddress());
        return java.util.List.copyOf(out);
    }
}
