package org.xbill.DNS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Cache;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Master;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.ResolverListener;
import org.xbill.DNS.Section;
import org.xbill.DNS.TSIG;
import org.xbill.DNS.Type;

/**
 * @author Wolfgang Nagele <mail@wnagele.com>
 */
public class RecursiveResolver implements Resolver {
	private final int MAX_RECURSION_STACK = 100;
	private final String ROOTS_FILE = "named.root";
	private final int RECURSIVE_QUERY_TIMEOUT = 1;

	private Message lookup(Set<Name> stack, String[] addresses, Message query) throws IOException {
		Message msg = getCached(query);
		if (msg != null)
			return msg;

		if (addresses == null)
			return null;
		Resolver resolver = createResolver(addresses);
		try {
			msg = resolver.send(query);
		} catch (IOException e) {
			return null;
		}
		if (msg == null)
			return null;

		// Found the authoritative answer
		if (msg.getHeader().getFlag(Flags.AA))
			return msg;

		Record[] authority = msg.getSectionArray(Section.AUTHORITY);
		for (Record record : authority) {
			if (Type.NS == record.getType()) {
				Name nameserver = ((NSRecord)record).getTarget();

				// Try to find glue for the record first
				Record[] additional = msg.getSectionArray(Section.ADDITIONAL);
				addresses = findAddresses(nameserver, additional);

				if (stack.contains(nameserver)) // Loop - cannot go there
					continue;
				stack.add(nameserver);
				if (stack.size() > MAX_RECURSION_STACK) // Prevent recursion spinning out of control
					return null;

				// No glue found - lookup target recursively
				if (addresses == null)
					addresses = findAddressesRecursive(stack, nameserver);

				// Chase down to the next level
				Message resp = lookup(stack, addresses, query);
				if (resp != null) {
					addCached(resp);
					return resp;
				}
			}
		}

		return null; // Just couldn't do it
	}

	private String[] findAddressesRecursive(Set<Name> stack, Name target) throws IOException {
		String[] ipv4Addresses = null;
		String[] ipv6Addresses = null;
		Message ipv4 = lookup(stack, getRoots(), Message.newQuery(Record.newRecord(target, Type.A, DClass.IN)));
		if (ipv4 != null)
			ipv4Addresses = findAddresses(target, ipv4.getSectionArray(Section.ANSWER));
		Message ipv6 = lookup(stack, getRoots(), Message.newQuery(Record.newRecord(target, Type.AAAA, DClass.IN)));
		if (ipv6 != null)
			ipv6Addresses = findAddresses(target, ipv6.getSectionArray(Section.ANSWER));

		String[] addresses = new String[0];
		if (ipv4Addresses != null)
			addresses = ipv4Addresses;
		if (ipv6Addresses != null) {
			String[] concatAddresses = new String[addresses.length + ipv6Addresses.length];
			System.arraycopy(addresses, 0, concatAddresses, 0, addresses.length);
			System.arraycopy(ipv6Addresses, 0, concatAddresses, addresses.length, ipv6Addresses.length);
			addresses = concatAddresses;
		}

		if (addresses.length == 0)
			return null;
		return addresses;
	}

	private String[] findAddresses(Name target, Record[] records) {
		ArrayList<String> addresses = new ArrayList<String>();
		for (Record record : records) {
			if (target == null || target.equals(record.getName())) {
				int recordType = record.getType();
				if (Type.A == recordType)
					addresses.add(((ARecord)record).getAddress().getHostAddress());
				else if (Type.AAAA == recordType)
					addresses.add(((AAAARecord)record).getAddress().getHostAddress());
			}
		}

		if (addresses.size() == 0)
			return null;
		return addresses.toArray(new String[addresses.size()]);
	}

	public Message send(Message query) throws IOException {
		Message msg = lookup(new HashSet<Name>(), getRoots(), query);
		if (msg == null) {
			msg = new Message(query.getHeader().getID());
			msg.getHeader().setRcode(Rcode.SERVFAIL);
			msg.getHeader().setFlag(Flags.QR);
			msg.addRecord(query.getQuestion(), Section.QUESTION);
		}
		msg.getHeader().setID(query.getHeader().getID()); // Match up response id with query
		return msg;
	}

	public Object sendAsync(Message query, ResolverListener listener) {
		throw new UnsupportedOperationException("Asynchronous send is not supported by this resolver");
	}

	private void addCached(Message msg) {
		Cache cache = getCache();
		if (cache != null)
			cache.addMessage(msg);
	}

	private Message getCached(Message query) {
		Cache cache = getCache();
		if (cache == null)
			return null;

		Record question = query.getQuestion();
		RRset[] rrsets = cache.findAnyRecords(question.getName(), question.getType());
		if (rrsets == null)
			return null;

		Message msg = new Message();
		for (RRset rrset : rrsets) {
			@SuppressWarnings("unchecked")
			Iterator<Record> recordsIter = rrset.rrs();
			while (recordsIter.hasNext()) {
				msg.addRecord(recordsIter.next(), Section.ANSWER);
			}
		}
		return msg;
	}

	private Cache CACHE = null;
	public Cache getCache() {
		if (CACHE != null)
			return CACHE;

		CACHE = new Cache();
		return CACHE;
	}

	private String[] ROOTS = null;
	private String[] getRoots() {
		if (ROOTS != null)
			return ROOTS;

		try {
			Master master = new Master(ROOTS_FILE);
			Record record;
			ArrayList<Record> records = new ArrayList<Record>();
			while ((record = master.nextRecord()) != null)
				records.add(record);

			ROOTS = findAddresses(null, records.toArray(new Record[records.size()]));
			return ROOTS;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private Integer port = null;
	private Boolean tcp = null;
	private Boolean ignoreTruncation = null;
	private Integer ednsLevel = null;
	private Integer ednsPayloadSize = null;
	private Integer ednsFlags = null;
	@SuppressWarnings("rawtypes")
	private List ednsOptions = null;
	private TSIG key = null;

	private Resolver createResolver(String[] targets) throws IOException {
		// Shuffle input targets so we don't query the same all the time
		ArrayList<String> targetsList = new ArrayList<String>();
		for (String target : targets)
			targetsList.add(target);
		Collections.shuffle(targetsList);

		Resolver resolver = new ExtendedResolver(targetsList.toArray(new String[targetsList.size()]));
		resolver.setTimeout(RECURSIVE_QUERY_TIMEOUT);
		if (port != null)
			resolver.setPort(port);
		if (tcp != null)
			resolver.setTCP(tcp);
		if (ignoreTruncation != null)
			resolver.setIgnoreTruncation(ignoreTruncation);
		if (ednsLevel != null) {
			if (ednsPayloadSize != null && ednsFlags != null && ednsOptions != null)
				resolver.setEDNS(ednsLevel, ednsPayloadSize, ednsFlags, ednsOptions);
			else
				resolver.setEDNS(ednsLevel);
		}
		if (key != null)
			resolver.setTSIGKey(key);
		return resolver;
	}

	public void setPort(int port) {
		this.port = port;
	}
	public void setTCP(boolean tcp) {
		this.tcp = tcp;
	}
	public void setIgnoreTruncation(boolean ignoreTruncation) {
		this.ignoreTruncation = ignoreTruncation;
	}
	public void setEDNS(int ednsLevel) {
		this.ednsLevel = ednsLevel;
	}
	@SuppressWarnings("rawtypes")
	public void setEDNS(int ednsLevel, int ednsPayloadSize, int ednsFlags, List ednsOptions) {
		this.ednsLevel = ednsLevel;
		this.ednsPayloadSize = ednsPayloadSize;
		this.ednsFlags = ednsFlags;
		this.ednsOptions = ednsOptions;
	}
	public void setTSIGKey(TSIG key) {
		this.key = key;
	}
	public void setTimeout(int timeoutSecs, int timeoutMsecs) {
		throw new UnsupportedOperationException("Timeout cannot be set for this resolver");
	}
	public void setTimeout(int timeoutSecs) {
		throw new UnsupportedOperationException("Timeout cannot be set for this resolver");
	}
}