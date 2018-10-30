package util;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Random;
import java.util.Stack;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stax.StAXSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.SchemaFactory;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.utils.Base64;

/*
 * @author	Subir Paul (OS:IT:ES:EST:PA:S1)
 * 
 */
public class UtilShared {
	protected static Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

	public static int maxAttemptsToCreateNewFile = 10;
	public static String defaultKeystoreType = "pkcs12";
	public static String certificateType = "X.509";
	
	public static int defaultBufSize = 16 * 1024;
	public static int defaultChunkStreamingSize = 32 * 1024;
	
	private static Random randomInt = new Random(System.currentTimeMillis());
	private static Random randomLong = new Random(System.currentTimeMillis());
	private static Random randomBoolean = new Random(System.currentTimeMillis());
	private static Random randomDouble = new Random(System.currentTimeMillis());
	
	public static class XmlTag {
		public QName qname;
		public String nsuri = "";
		public XmlTag(QName qname) {
			this.qname = qname;
		}
		
		@Override
		public String toString() {
			return getStartTag();
		}
		
		public String getStartTag() {
			StringBuilder sb = new StringBuilder();
			sb.append("<");
			String prefix = qname.getPrefix();
			if (prefix != null && !"".equals(prefix)) {
				sb.append(prefix); 
				sb.append(":");
			}
			sb.append(qname.getLocalPart());
			if (nsuri != null && !"".equals(nsuri)) {
				sb.append(" ");
				sb.append(nsuri);
			} 
			sb.append(">");
			return sb.toString();
		}
		
		public String getEndTag() {
			StringBuilder sb = new StringBuilder();
			sb.append("</");
			String prefix = qname.getPrefix();
			if (prefix != null && !"".equals(prefix)) {
				sb.append(prefix); 
				sb.append(":");
			}
			sb.append(qname.getLocalPart());
			sb.append(">");
			return sb.toString();
		}
	}
	
	public static boolean validateSchema(String xmlFile, String schemaFile) throws Exception {
		return validateSchema(xmlFile, schemaFile, null);
	}
	
	public static boolean validateSchema(String xmlFile, String schemaFile, String startElem) throws Exception {
		logger.debug("--> validateSchema(). xmlFile=" + xmlFile + ", schemaFile=" + schemaFile + ", startElem=" + startElem);
		boolean success = false;
		XMLStreamReader reader = null;
		BufferedReader br = null;
		try {
			QName qname = null;
			if (startElem != null) {
				String elem = null, ns = null;
				Pattern pattern = Pattern.compile("\\{([^}]*)\\}|.+");
				Matcher matcher = pattern.matcher(startElem);
				while (matcher.find()) {
					if (matcher.group().startsWith("{"))
						ns = matcher.group(1);
					else {
						elem = matcher.group();
						break;
					}
				}
				if (ns != null)
					qname = new QName(ns, elem);
			}
			br = new BufferedReader(new FileReader(xmlFile));
			reader = XMLInputFactory.newFactory().createXMLStreamReader(br);
			while(reader.hasNext()) {
				if (reader.getEventType() == XMLStreamConstants.START_ELEMENT) {
					if (startElem == null)
						break;
					if (qname == null && startElem.equalsIgnoreCase(reader.getName().getLocalPart()))
						break;
					if (qname != null && qname.equals(reader.getName()))
						break;
				}
				reader.next();
			}
			if (reader.getEventType() == XMLStreamConstants.END_DOCUMENT)
				throw new Exception(startElem + " element not found");
			logger.debug("StartElement=" + reader.getName());
			//logger.debug("vaLidation about to start. time=" + new Date());
			if (schemaFile.startsWith("http"))
				SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema").newSchema(new URL(schemaFile))
				.newValidator().validate(new StAXSource(reader));
			else
				SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema").newSchema(new File(schemaFile))
				.newValidator().validate(new StAXSource(reader));
			success = true;
			//logger.debug("vaLidation ended. time=" + new Date());
			reader.close();
			br.close();
			reader = null;
			br = null;
		} catch(Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
		} finally {
			if (reader != null) try{reader.close();}catch(Exception e) {}
			if (br != null) try{br.close();}catch(Exception e) {}
		}
		logger.debug("Schema Validation Success=" + success + ", xmlFile=" + xmlFile + ", schemaFile=" + schemaFile + ", startElem=" + startElem);
		logger.debug("<-- validateSchema()");
		return success;
	}
	
	public static char[] stripCR(char[] buf, int len) {
		if (len <= 0 || len > buf.length) len = buf.length;
		char[] tmp = new char[len];
		int count = 0;
		for (int i = 0; i < len; i++) {
			if (buf[i] == '\r')
				continue;
			tmp[count++] = buf[i];
		}
		char[] newbuf = new char[count];
		System.arraycopy(tmp, 0, newbuf, 0, newbuf.length);
		return newbuf;
	}
	
	public static char[] leftTrim(char[] buf) {
		int i = 0;
		for (; i < buf.length; i++) {
			if (!Character.isWhitespace(buf[i]))
				break;
		}
		if (i == 0) return buf;
		char[] newbuf = new char[buf.length-i];
		System.arraycopy(buf, i, newbuf, 0, newbuf.length);
		return newbuf;
	}

	//return null if inbuf do not have sufficient data to strip xml declaration and then find a non-whitespace data  
	public static char[] stripXmlHeader(char[] in) {
		//<?xml version="1.0" encoding="UTF-8" standalone="no"?>
		//System.out.println(new String(in));
		char[] buf = leftTrim(in);
		String prefix = "<?xml ", suffix = "?>";
		if (buf.length < (prefix.length() + suffix.length()))
			return null;
		String tmp = new String(buf);
		if (buf[0] == '<') {
			if (!tmp.startsWith(prefix))
				return tmp.toCharArray();
		}
		int pos = tmp.indexOf(suffix, prefix.length());
		if (pos == -1)
			return null;
		tmp = tmp.substring(pos + suffix.length());
		buf = leftTrim(tmp.toCharArray());
		if (buf.length == 0)
			return null;
		return buf;
	}
	
	public static byte[] append(byte[] buf, String dataToAppend) {
		return append(buf, dataToAppend.getBytes());
	}
	
	public static byte[] append(byte[] buf, byte[] dataToAppend) {
		byte[] tmp = new byte[buf.length+dataToAppend.length];
		System.arraycopy(buf, 0, tmp, 0, buf.length);
		System.arraycopy(dataToAppend, 0, tmp, buf.length, dataToAppend.length);
		return tmp;
	}
	
	public static String genUniqueRandomId() {
		UUID uuid = UUID.randomUUID();
		return uuid + "@" + System.identityHashCode(uuid);
	}
	
	public static BigDecimal genRandomDecimal(double low, double high) {
		double d;
		synchronized (randomDouble) {
			d = randomDouble.nextDouble();
		}
		d = low + d * (high - low);
		return new BigDecimal(d).setScale(2, RoundingMode.HALF_EVEN);
	}
	
	public static long genRandomPositiveLong() {
		long l;
		synchronized (randomLong) {
			l = randomLong.nextLong();
		}
		if (l < 0)
			l *= -1;
		return l;
	}

	public static boolean genRandomBoolean() {
		synchronized (randomBoolean) {
			return randomBoolean.nextBoolean();
		}
	}

	public static int genRandomPositiveInt() {
		int i;
		synchronized (randomInt) {
			i = randomInt.nextInt();
		}
		if (i < 0)
			i *= -1;
		return i;
	}

	public static int genRandomInt(int low, int high) {
		if (low >= high)
			return low;
		synchronized (randomInt) {
			return randomInt.nextInt(high-low) + low;
		}
	}
	
	public static void cleanFolder(File dir) {
		if (dir.exists() && dir.isDirectory()) {
			String[] files = dir.list();
			File file;
			for (int i = 0; i < files.length; i++) {
				file = new File(dir.getAbsolutePath() + File.separator + files[i]);
				if (!file.isDirectory())
					file.delete();
			}
		}
	}
	
	public static void deleteDestAndRenameFile(File src, File dest) throws Exception {
		if (!src.getAbsolutePath().equals(dest.getAbsolutePath())) {
			int attempts = maxAttemptsToCreateNewFile;
			while (attempts-- > 0 && dest.exists() && !dest.delete())
				Thread.sleep(100);
			if (attempts <= 0)
				throw new Exception("unable to rename " + src.getAbsolutePath() + " to " + dest.getAbsolutePath());
			attempts = maxAttemptsToCreateNewFile;
			while (attempts-- > 0 && !src.renameTo(dest))
				Thread.sleep(100);
			if (attempts <= 0)
				throw new Exception("unable to rename " + src.getAbsolutePath() + " to " + dest.getAbsolutePath());
			if (src.exists() && !src.delete()) src.deleteOnExit();
		}
	}
	
    public static void printNode(Node node) {
		logger.debug("--> printNode() " + node.getNodeName());
		logger.debug("prefix=" + node.getPrefix() + ", baseuri=" + node.getBaseURI() + ", nsuri=" + node.getNamespaceURI() + ", value=" + node.getNodeValue());
		if (node.getFirstChild() != null) {
			logger.debug("--> Child of " + node.getNodeName() );
			printNode(node.getFirstChild());
			logger.debug("<-- Child of " + node.getNodeName() );
		}
		if (node.getNextSibling() != null) {
			logger.debug("--> Sibling of " + node.getNodeName() );
			printNode(node.getNextSibling());
			logger.debug("<-- Sibling of " + node.getNodeName() );
		}
		logger.debug("<-- printNode() " + node.getNodeName());
	}
	
	public static Certificate getCert(String certfile) throws Exception {
		try {
			CertificateFactory cf = CertificateFactory.getInstance(certificateType);
		    FileInputStream fs = new FileInputStream(new File(certfile));
		    Certificate cert = cf.generateCertificate(fs);
		    fs.close();
		    return cert;
		} catch (Exception e) {
			logger.debug(e.getMessage(), e);
			throw e;
		}
	}
	
	public static X509Certificate getCert(String keystorefile, String keystorepwd) throws Exception {
		return getCert(defaultKeystoreType, keystorefile, keystorepwd, null);
	}
	
	public static X509Certificate getCert(String keystorefile, String keystorepwd, String alias) throws Exception {
		return getCert(defaultKeystoreType, keystorefile, keystorepwd, alias);
	}
	
	public static X509Certificate getCert(String keystoretype, String keystorefile, String keystorepwd, String alias) throws Exception {
		try {
			//KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			KeyStore keystore = KeyStore.getInstance(keystoretype);
			FileInputStream fis = new FileInputStream(new File(keystorefile));
			keystore.load(fis, keystorepwd.toCharArray());
			fis.close();
			if (alias == null) {
				Enumeration<String> e = keystore.aliases();
				if (e.hasMoreElements())
					alias = e.nextElement();
			}
			if (alias != null) {
				X509Certificate cert = (X509Certificate)keystore.getCertificate(alias);
				return cert;
			}
		} catch (Exception e) {
			logger.debug(e.getMessage(), e);
			throw e;
		}
		return null;
	}

	public static PrivateKey getPrivateKey(String keystorefile, String keystorepwd, String keypwd, String alias) throws Exception {
		return getPrivateKey(defaultKeystoreType, keystorefile, keystorepwd, keypwd, alias);
	}
	
	public static PrivateKey getPrivateKey(String keystorefile, String keystorepwd, String keypwd) throws Exception {
		return getPrivateKey(defaultKeystoreType, keystorefile, keystorepwd, keypwd, null);
	}
	
	public static PrivateKey getPrivateKey(String keystoretype, String keystorefile, String keystorepwd, String keypwd, String alias) throws Exception {
		try {
			//KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			KeyStore keystore = KeyStore.getInstance(keystoretype);
			FileInputStream fis = new FileInputStream(new File(keystorefile));
			keystore.load(fis, keystorepwd.toCharArray());
			fis.close();
			if (alias == null) {
				Enumeration<String> e = keystore.aliases();
				if (e.hasMoreElements())
					alias = e.nextElement();
			}
			if (alias != null) {
				PrivateKey privkey = (PrivateKey)keystore.getKey(alias, keypwd.toCharArray());
				if (privkey == null)
					privkey = (PrivateKey)keystore.getKey(alias.toLowerCase(), keypwd.toCharArray());
				return privkey;
			}
		} catch (Exception e) {
			logger.debug(e.getMessage(), e);
			throw e;
		}
		return null;
	}
	
	public static PublicKey getPublicKey(PrivateKey privKey) throws Exception {
		PublicKey pubKey = null;
		if (privKey instanceof RSAPrivateCrtKey) {
			RSAPrivateCrtKey rsa = (RSAPrivateCrtKey)privKey;
			pubKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent()));
		}
		return pubKey;
	}
	
	public static String getNodeXml(Node node) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer trans = transformerFactory.newTransformer();
        trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter sw = new StringWriter();
        trans.transform(new DOMSource(node), new StreamResult(sw));
        return sw.getBuffer().toString();
	}
	   
	public static Element getElementWithASpecificAttribute(Element startelem, String targetAttr, String targetAttrVal) throws Exception {
		NodeList nl;
		Node node;
		Element elem = null;
		if (startelem.hasAttribute(targetAttr) && startelem.getAttribute(targetAttr).equals(targetAttrVal))
			elem = startelem;
		else {
			nl = startelem.getChildNodes();
			for (int i = 0; i < nl.getLength(); i++) {
				node = nl.item(i);
				if (node instanceof Element) {
					elem = getElementWithASpecificAttribute((Element)node, targetAttr, targetAttrVal);
					if (elem != null)
						break;
				}
			}
		}
		return elem;
	}
	
	public static void createBinaryFileFromSignedBase64BinaryFile(String infile, String outfile) throws Exception {
		logger.debug("--> createBinaryFileFromSignedBase64BinaryFile(). infile=" + infile + ", outfile=" + outfile);
		BufferedReader br = null;
		BufferedOutputStream bos = null;
		try {
			if (!Init.isInitialized())
				Init.init();
			String line; int pos;
			boolean isBase64StartFound = false;
			byte[] buf;
			br = new BufferedReader(new FileReader(new File(infile)));
			bos = new BufferedOutputStream(new FileOutputStream(new File(outfile)));
			while((line = br.readLine()) != null) {
				line = line.trim();
				if (!isBase64StartFound && (pos = line.indexOf("Object")) != -1) {
					line = line.substring(pos+"Object".length());
					pos = line.indexOf('>');
					if (pos == -1)
						throw new Exception("'>' closing bracket is missing for <Object");
					line = line.substring(pos+1);
					// <Object><SignatureProperties Id="ObjRefId"><SignatureProperty Target="#SignatureId">JVBERi0xLjYNJeLjz9MNCjI0IDAgb2JqDTw8L0xpbmVhcml6ZWQgMS9MIDcyMzYvTyAyNi9FIDIz
					while(true) {
						if (line.length() == 0) {
							line = br.readLine();
							if (line == null)
								throw new Exception("unexpected EOF encountered");
							line = line.trim();
						}
						if (line.startsWith("<")) {
							pos = line.indexOf('>');
							if (pos != -1)
								line = line.substring(pos+1);
							else 
								throw new Exception ("missing > in " + line);
						} else {
							isBase64StartFound = true;
							break;
						}
					}
				}
				if (isBase64StartFound) {
					//check for end tag/s
					pos = line.indexOf('<');
					if (pos != -1)
						line = line.substring(0, pos);
					buf = Base64.decode(line.getBytes());
					bos.write(buf);
					if (pos != -1)
						break;
				}
			}
			br.close(); br = null;
			bos.close(); bos = null;
		} finally {
			if (br != null) try{br.close();}catch(Exception e){}
			if (bos != null) try{bos.close();}catch(Exception e){}
		}
		logger.debug("<-- createBinaryFileFromSignedBase64BinaryFile()");
	}

	private static Object getTmpFileNameLock = new Object();
	public static String getTmpFileName(String folder, String prefix, String suffix) throws Exception {
		synchronized (getTmpFileNameLock) {
			//replace : and | (we support multiple files separated by : or |)
			prefix = prefix.replace(":", "_").replace("|", "_");
			if (folder == null)
				folder = "";
			if (!"".equals(folder) && !folder.endsWith("/") && !folder.endsWith("\\"))
				folder += File.separator;
			int attempts = maxAttemptsToCreateNewFile;
			String xmlfilename = null; 
			File file;
			if (prefix != null && !"".equals(prefix))
				prefix += ".";
			if (suffix != null && !"".equals(suffix) && !suffix.startsWith("."))
				suffix = "." + suffix;
			while(attempts-- > 0) {
				xmlfilename = folder + prefix + UUID.randomUUID() + suffix;
				file = new File(xmlfilename);
				if (!file.exists() && file.createNewFile())
					break;
			}
			if (attempts <= 0)
				throw new Exception ("Unable to getFileName()");
			return xmlfilename;
		}
	}

	public static String getTmpFileName(String infile, String suffix) throws Exception {
		//replace : and | (we support multiple files separated by : or |)
		infile = infile.replace(":", "_").replace("|", "_");
		File file = new File(infile);
		String folder = "";
		if (file.getParent() != null)
			folder = file.getAbsoluteFile().getParent();
		String ret = getTmpFileName(folder, file.getName(), suffix);
        return ret;
	}

	public static File renameToNextSequencedFile(String srcfile) throws Exception {
		return renameToNextSequencedFile(srcfile, null, null, null);
	}
	
	private static Object renameToNextSequencedFileLock = new Object();
	public static File renameToNextSequencedFile(String srcfile, String destfolder, String prefix, String suffix) throws Exception {
		synchronized (renameToNextSequencedFileLock) {
			//replace : and | (we support multiple files separated by : or |)
			srcfile = srcfile.replace(":", "_").replace("|", "_");
			prefix = prefix.replace(":", "_").replace("|", "_");
			File src = new File(srcfile);
			File dest = null;
			int count = 0;
			if (destfolder == null) {
				if (src.getParent() != null)
					destfolder = src.getAbsoluteFile().getParent();
				else
					destfolder = "";
			}
			int pos;
			if (prefix == null) {
				if ((pos = srcfile.lastIndexOf('.')) != -1) {
					prefix = srcfile.substring(0, pos);
					if (suffix == null)
						suffix = srcfile.substring(pos);
				}
			}
			while (true) {
				dest = new File(destfolder + prefix + "_" + count++ + suffix);
				if (!dest.exists()) {
					 break;
				}
			}
			if (!src.renameTo(dest))
				throw new Exception("unable to rename " + src + " to " + dest);
			if (src.exists() && !src.delete()) src.deleteOnExit();
			return dest;
		}
	}
	
	public static String getElapsedTime(Date starttime) {
		Date endtime = new Date();
		long duration = endtime.getTime() - starttime.getTime();
		int hour = (int)(duration / (3600 * 1000));
		duration -= hour * 3600 * 1000;
		int minute = (int)(duration / (60 * 1000));
		duration -= minute * 60 * 1000;
		int sec = (int)(duration / 1000);
		duration -= sec * 1000;
		int millis = (int)duration;
		StringBuilder sb = new StringBuilder("Elapsed time: ");
		if (hour > 0)
			sb.append(hour + " hours, ");
		if (minute > 0)
			sb.append(minute + " minutes, ");
		if (sec > 0)
			sb.append(sec + " sec, ");
		if (millis > 0)
			sb.append(millis + " millisecond");
		return sb.toString();
	}
	
    public static String[] getFiles(String file) {
    	String[] arr = file.split("\\|");
    	if (arr.length == 1)
    		arr = file.split(":");
    	return arr;
    }

	public static void extractUnsignedXmlFromSignedXml(String signedXml, String unsignedXmlStartElem, String outUnsignedXml) throws Exception {
		String[] startElems = getFiles(unsignedXmlStartElem);
		String[] outXmls = getFiles(outUnsignedXml);
		if (startElems.length > outXmls.length) {
			String[] arr = new String[outXmls.length];
			System.arraycopy(startElems, 0, arr, 0, arr.length);
			startElems = arr;
		} else if (startElems.length < outXmls.length) {
			String[] arr = new String[outXmls.length];
			for (int i = 0; i < arr.length; i++) {
				if (i < startElems.length)
					arr[i] = startElems[i];
				else
					arr[i] = startElems[startElems.length-1];
			}
			startElems = arr;
		}
		extractUnsignedXmlFromSignedXml(signedXml,  startElems, outXmls);
	}
	
	//usage: extractUnsignedXmlFromSignedXml(signedXml, FATCA_OECD, unsignedXml) or extractUnsignedXmlFromSignedXml(signedXml, CRS_OECD, unsignedXml)
	public static void extractUnsignedXmlFromSignedXml(String signedXml, String[] unsignedXmlStartElem, String[] outUnsignedXml) throws Exception {
		logger.debug("--> extractUnsignedXmlFromSignedXml(). signedXml=" + signedXml);
		if (signedXml == null)
			throw new Exception("signedXml must be non-null");
		if (outUnsignedXml == null || outUnsignedXml.length == 0)
			throw new Exception("outUnsignedXml must be non-null and non-zero array");
		if (unsignedXmlStartElem == null || unsignedXmlStartElem.length == 0)
			throw new Exception("unsignedXmlStartElement must be non-null and non-zero array");
		if (outUnsignedXml.length != unsignedXmlStartElem.length)
			throw new Exception("outUnsignedXml array and unsignedXmlStartElement arrray length must be same");
		FileInputStream fis = null;
		XMLStreamReader rd = null;
		BufferedWriter bw = null;
		boolean finished = false, objectFound = false, referencedElemFound = false, startElemFound = false, signedInfoFound = false, standalone = false;
		ArrayList<String> refs = new ArrayList<>(); 
		String name, prefix, nsuri, curRefId = null, val, version, encoding;
		Stack<Object> stackUnsignedElemTag = new Stack<>(), stackReferencedElemTag = new Stack<>();
		int curIndex = 0;
		StringBuilder sbElem = new StringBuilder();
		String xmlDecl = null;
		try {
			fis = new FileInputStream(new File(signedXml));
			rd = XMLInputFactory.newFactory().createXMLStreamReader(fis);
			version = rd.getVersion();
			encoding = rd.getEncoding();
			standalone = rd.isStandalone();
			xmlDecl = "<?xml version=\""+(version==null?"1.0":version)+"\" encoding=\""+(encoding==null?"UTF-8":encoding)+"\" standalone=\""+(standalone?"yes":"no")+"\"?>";
			while (!finished && rd.hasNext()) {
				switch(rd.getEventType()) {
				case XMLStreamConstants.START_ELEMENT:
					name = rd.getLocalName();
					nsuri = rd.getNamespaceURI();
					if (!signedInfoFound) {
						if (XMLSignature.XMLNS.equals(nsuri) && "SignedInfo".equals(name))
							signedInfoFound = true;
					} else {
						if (XMLSignature.XMLNS.equals(nsuri) && "Reference".equals(name)) {
							curRefId = rd.getAttributeValue(null, "URI");
							//only same doc ref URI=#<refid> allowed
							int pos = curRefId.indexOf("#");
							if (pos != -1)
								curRefId = curRefId.substring(pos+1);
							if (curRefId != null)
								refs.add(curRefId);
						}
					}
					break;
				case XMLStreamConstants.END_ELEMENT:
					name = rd.getLocalName();
					nsuri = rd.getNamespaceURI();
					if (XMLSignature.XMLNS.equals(nsuri) && "SignedInfo".equals(name))
						finished = true;
					break;
				}
				rd.next();
			}
			finished = false;
			while (!finished && rd.hasNext()) {
				sbElem.setLength(0);
				switch(rd.getEventType()) {
				case XMLStreamConstants.START_ELEMENT:
					name = rd.getLocalName();
					nsuri = rd.getNamespaceURI();
					prefix = rd.getPrefix();
					//find Object tag. Unsigned xml is nested within Object
					if (!startElemFound && !objectFound && !referencedElemFound && XMLSignature.XMLNS.equals(nsuri) && "Object".equals(name))
						objectFound = true;
					//Object, SignatureProperty, SignatureProperties may have referenced element (signed xml frag that contains unsigned xml)
					if (!startElemFound && objectFound && !referencedElemFound && XMLSignature.XMLNS.equals(nsuri) &&
							(curRefId = rd.getAttributeValue(null, "Id")) != null &&	refs.contains(curRefId)) {
						referencedElemFound = true;
						stackReferencedElemTag.clear();
					}
					//start looking for start element from next element ('else' skips referenced element)
					else if (!startElemFound && objectFound && referencedElemFound && name.equals(unsignedXmlStartElem[curIndex])) {
						if (bw != null) bw.close();
						bw = new BufferedWriter(new FileWriter(new File(outUnsignedXml[curIndex])));
						bw.write(xmlDecl + "\n");
						startElemFound = true;
						stackUnsignedElemTag.clear();
						logger.debug("start extracting. refId=" + curRefId + ", startTag=" + unsignedXmlStartElem[curIndex]);
					}
					if (referencedElemFound)
						stackReferencedElemTag.add(0);
					//capture everything as soon as start element is found
					if (startElemFound) {
						//push something in stack at start element and pop at end element
						stackUnsignedElemTag.add(0);
						sbElem.append("<" + ("".equals(prefix) || prefix == null ? "" : prefix + ":") + name);
						for (int i = 0; i < rd.getNamespaceCount(); i++) {
							prefix = rd.getNamespacePrefix(i); 
							nsuri = rd.getNamespaceURI(i);
							if (nsuri == null)
								nsuri = "";
							else
								nsuri = nsuri.replace("'", "&apos;").replace("\"", "&quot;");
							nsuri = "\"" + nsuri + "\"";
							sbElem.append(" " + ("".equals(prefix) || prefix == null ? "xmlns=" + nsuri : "xmlns:" + prefix + "=" + nsuri));
						}
						for (int i = 0; i < rd.getAttributeCount(); i++) {
							name = rd.getAttributeLocalName(i); 
							prefix = rd.getAttributePrefix(i);
							val = rd.getAttributeValue(i).replace("'", "&apos;").replace("\"", "&quot;");;
							sbElem.append(" " + ("".equals(prefix) || prefix == null ? name : prefix + ":" + name) + "=\"" + val + "\"");
						}
						sbElem.append(">");
						bw.write(sbElem.toString());
					}
					break;
				case XMLStreamConstants.CHARACTERS:
					if (startElemFound) {
						sbElem.append(rd.getText().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"));
						bw.write(sbElem.toString());
					}
					break;
				case XMLStreamConstants.COMMENT:
					if (startElemFound) {
						sbElem.append("<!--" + rd.getText() + "-->");
						bw.write(sbElem.toString());
					}
					break;
				case XMLStreamConstants.END_ELEMENT:
					if (startElemFound) {
						prefix = rd.getPrefix();
						name = rd.getLocalName();
						sbElem.append("</" + ("".equals(prefix) || prefix == null ? "" : prefix + ":") + name + ">");
						bw.write(sbElem.toString());
						stackUnsignedElemTag.pop();
						//empty stack means we have reached corresponding end element of unsigned xml start element
						if (stackUnsignedElemTag.isEmpty()) {
							logger.debug("end extracting. refId=" + curRefId + ", startTag=" + unsignedXmlStartElem[curIndex]);							bw.close();
							bw = null;
							objectFound = referencedElemFound = startElemFound = false;
							curIndex++;
							if (curIndex >= outUnsignedXml.length || curIndex >= unsignedXmlStartElem.length)
								finished = true;
						}
					}
					if (referencedElemFound) {
						stackReferencedElemTag.pop();
						if (stackReferencedElemTag.isEmpty()) {
							objectFound = referencedElemFound = startElemFound = false;
							if (bw != null) {
								throw new Exception("bug? bw should be null here");
								//bw.close(); bw = null;
							}
						}
					}
					break;
				}
				rd.next();
			}
			rd.close();
			rd = null;
			fis.close();
			fis = null;
			if (bw != null)
				bw.close();
			bw = null;
		} finally {
			if (fis != null) try{fis.close();}catch(Throwable t){}
			if (rd != null) try{rd.close();}catch(Throwable t){}
			if (bw != null) try{bw.close();}catch(Throwable t){}
		}
		logger.debug("<-- extractUnsignedXmlFromSignedXml()");
	}
}
