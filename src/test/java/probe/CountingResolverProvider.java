package probe;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * Counts every name resolution the JVM performs, so "inspect does no DNS" can be observed rather
 * than asserted. Registered only on the test classpath; it is never part of the extension.
 */
public final class CountingResolverProvider extends InetAddressResolverProvider {
    public static final AtomicInteger FORWARD = new AtomicInteger();
    public static final AtomicInteger REVERSE = new AtomicInteger();

    @Override
    public InetAddressResolver get(Configuration configuration) {
        var builtin = configuration.builtinResolver();
        return new InetAddressResolver() {
            @Override
            public Stream<InetAddress> lookupByName(String host, LookupPolicy policy)
                    throws UnknownHostException {
                FORWARD.incrementAndGet();
                return builtin.lookupByName(host, policy);
            }

            @Override
            public String lookupByAddress(byte[] address) throws UnknownHostException {
                REVERSE.incrementAndGet();
                return builtin.lookupByAddress(address);
            }
        };
    }

    @Override
    public String name() {
        return "counting";
    }
}
