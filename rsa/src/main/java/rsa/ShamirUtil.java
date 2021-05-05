package rsa;

import java.security.SecureRandom;
import java.util.logging.Logger;

import java.util.Map;
import com.codahale.shamir.Scheme;

public class ShamirUtil {
	
	
	
	private final static Logger log = Logger.getLogger(ShamirUtil.class.getName());

	// split function
	public static final Map<Integer, byte[]> shamirSplit(final int n, final int k, final byte[] data) {
		final Scheme scheme = new Scheme(new SecureRandom(), n, k);
		final Map<Integer, byte[]> parts = scheme.split(data);
		return parts;
	}

	// joins data using shamir parts
	// n the number of parts to produce (must be >1) k the threshold of joinable
	// parts (must be <= n)
	public static final byte[] shamirJoin(final int n, final int k, final Map<Integer, byte[]> parts) {
		final Scheme scheme = new Scheme(new SecureRandom(), n, k);
		final byte[] recovered = scheme.join(parts);
		return recovered;
	}

}
