package fatca.util;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.UUID;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLSignature.SignatureValue;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.utils.Base64;

import fatca.intf.IPackager;

/*
 * @author	Subir Paul (IT:ES:SE:PE)
 * 
 */
public class UtilShared {
	protected static Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

	private static Random randomInt = new Random(System.currentTimeMillis());
	private static Random randomLong = new Random(System.currentTimeMillis());
	private static Random randomBoolean = new Random(System.currentTimeMillis());
	private static Random randomDouble = new Random(System.currentTimeMillis());
	
	public static String stripXmlHeader(String tmp) {
		if (tmp.startsWith("<?xml")) {
			int pos = tmp.indexOf(">");
			if (pos != -1) {
				tmp = tmp.substring(pos+1);
				boolean stripWS = false;
				int i;
				for (i = 0; i < tmp.length(); i++) {
					if (Character.isWhitespace(tmp.charAt(i)))
						stripWS = true;
					else
						break;
				}
				if (stripWS)
					tmp = tmp.substring(i);
			}
		}
		return tmp;
	}
	
	public static String genRandomId() {
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
			int attempts = IPackager.maxAttemptsToCreateNewFile;
			while (attempts-- > 0 && dest.exists() && !dest.delete())
				Thread.sleep(100);
			if (attempts <= 0)
				throw new Exception("unable to rename " + src.getAbsolutePath() + " to " + dest.getAbsolutePath());
			attempts = IPackager.maxAttemptsToCreateNewFile;
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
			CertificateFactory cf = CertificateFactory.getInstance(IPackager.certificateType);
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
		return getCert(IPackager.defaultKeystoreType, keystorefile, keystorepwd, null);
	}
	
	public static X509Certificate getCert(String keystorefile, String keystorepwd, String alias) throws Exception {
		return getCert(IPackager.defaultKeystoreType, keystorefile, keystorepwd, alias);
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
		return getPrivateKey(IPackager.defaultKeystoreType, keystorefile, keystorepwd, keypwd, alias);
	}
	
	public static PrivateKey getPrivateKey(String keystorefile, String keystorepwd, String keypwd) throws Exception {
		return getPrivateKey(IPackager.defaultKeystoreType, keystorefile, keystorepwd, keypwd, null);
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
	
	protected static class KeyValueKeySelector extends KeySelector {
		public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, 
				AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
			if (keyInfo == null)
				throw new KeySelectorException("Null KeyInfo");
			List<?> list = keyInfo.getContent();
			PublicKey pk = null;

			for (int i = 0; i < list.size(); i++) {
				XMLStructure xmlStructure = (XMLStructure) list.get(i);
				if (xmlStructure instanceof KeyValue) {
					try {
						pk = ((KeyValue)xmlStructure).getPublicKey();
					} catch(KeyException ke) {
						throw new KeySelectorException(ke.getMessage());
					}
					break;
				} else if (xmlStructure instanceof X509Data) {
					X509Data x509data = (X509Data)xmlStructure;
					List<?> x509datalist = x509data.getContent();
					for (int j = 0; j < x509datalist.size(); j++) {
						if (x509datalist.get(j) instanceof X509Certificate) {
							X509Certificate cert = (X509Certificate)x509datalist.get(j);
							pk = cert.getPublicKey();
							break;
						}
					}
				}
			}
			if (pk != null) {
				final PublicKey retpk = pk;
				logger.debug("PublicKey from XML=" + pk);
				return new KeySelectorResult() {public Key getKey(){return retpk;}};
			}
			throw new KeySelectorException("Missing KeyValue");
		}
	}
	
	public static String getNodeXml(Node node) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer trans = transformerFactory.newTransformer();
        trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter sw = new StringWriter();
        trans.transform(new DOMSource(node), new StreamResult(sw));
        return sw.getBuffer().toString();
	}
	   
	public static boolean verifySignatureDOM(String signedPlainTextFile) throws Exception  {
		return verifySignatureDOM(signedPlainTextFile, null);
	}
	
	public static boolean verifySignatureDOM(String signedFile, PublicKey sigkey) throws Exception  {
		return verifySignatureDOM(signedFile, sigkey, true);
	}
	
	public static boolean verifySignatureDOM(String signedFile, PublicKey sigkey, boolean useFakeElem) throws Exception  {
		logger.debug("--> verifySignatureDOM(). signedFile=" + signedFile + ", sigkey=" + sigkey + ", useFakeElem=" + useFakeElem);
		boolean ret = false;
		XMLSignatureFactory xmlSigFactory;
		XMLSignature signature;
		NodeList nl;
		DocumentBuilderFactory dbf;
		Document doc;
		DOMValidateContext valContext;
		boolean coreValidity, sigValValidity, refValid;
		Iterator<?> iter;
		Element objNode=null, fakeObjNode=null;
		boolean isFakeElem = useFakeElem;
		try {
			xmlSigFactory = XMLSignatureFactory.getInstance();
			dbf = DocumentBuilderFactory.newInstance();
	        dbf.setNamespaceAware(true);
	        DocumentBuilder db = dbf.newDocumentBuilder();
	        doc = db.parse(new File(signedFile));
	        //fakeObjNode is to reduce memory foot print
	        nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Object");
			if (nl.getLength() == 0)
				nl = doc.getElementsByTagName("Object");
			if (nl.getLength() == 0)
			    throw new Exception("Cannot find Object element");
			if (isFakeElem) {
				// this reduces foot print
				objNode = (Element)nl.item(0);
				String id = "";
				Node attrId = objNode.getAttributes().getNamedItem("Id");
				if (attrId  != null)
					id = attrId.getTextContent();
				fakeObjNode = doc.createElementNS(XMLSignature.XMLNS, "Object");
				fakeObjNode.setAttribute("Id", id);
				try {
					doc.getDocumentElement().replaceChild(fakeObjNode, objNode);
				} catch(Exception e) {
					isFakeElem = false;
				}
			}
	    	nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
			if (nl.getLength() == 0)
			    throw new Exception("Cannot find Signature element");
			Node sigNode = nl.item(0);
	    	if(sigkey != null)
				valContext = new DOMValidateContext(sigkey, sigNode);
			else
				valContext = new DOMValidateContext(new KeyValueKeySelector(), sigNode);
			logger.debug("isFakeElem=" + isFakeElem);
			if (isFakeElem) {
				//very important - replace fakeobject with real one
				doc.getDocumentElement().replaceChild(objNode, fakeObjNode);
			}
	        signature = xmlSigFactory.unmarshalXMLSignature(valContext);
		    coreValidity = signature.validate(valContext);
			logger.debug("Signature core validation " + coreValidity);
		    SignatureValue sigval = signature.getSignatureValue();
		    sigValValidity = sigval.validate(valContext);
		    logger.debug("SignatureValue validation status: " + sigValValidity);
	        iter = signature.getSignedInfo().getReferences().iterator();
	        Reference ref;
	        boolean refValidFlag = true;
	        for (int j=0; iter.hasNext(); j++) {
	        	ref = (Reference) iter.next();
	        	refValid = ref.validate(valContext);
	        	logger.debug("ref["+j+"] validity status: " + refValid);
	        	refValidFlag = refValidFlag && refValid;
	        	logger.debug("ref.getURI()=" + ref.getURI());
	        	logger.debug("ref.getCalculatedDigestValue()=" + Base64.encode(ref.getCalculatedDigestValue()));
	        	logger.debug("ref.getReferencedDigestValue()=" + Base64.encode(ref.getDigestValue()));
	        	List<?> lt = ref.getTransforms();
	        	Transform tr;
	        	for (int i = 0; i < lt.size(); i++) {
	        		tr = (Transform)lt.get(i);
	        		logger.debug("transform.getAlgorithm()=" + tr.getAlgorithm());
	        	}
	        }
			ret = coreValidity & sigValValidity & refValidFlag;
			logger.debug("signature validated=" + ret);
		} catch (Exception e) {
			e.printStackTrace();
			//throw e; // do not throw
		} finally {
		}
		logger.debug("<-- verifySignatureDOM()");
		return ret;
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
					// <Object><SignatureProperties Id="FATCA"><SignatureProperty Target="#SignatureId">JVBERi0xLjYNJeLjz9MNCjI0IDAgb2JqDTw8L0xpbmVhcml6ZWQgMS9MIDcyMzYvTyAyNi9FIDIz
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

	public static String getTmpFileName(String folder, String prefix, String suffix) throws Exception {
		if (folder == null)
			folder = "";
		if (!"".equals(folder) && !folder.endsWith("/") && !folder.endsWith("\\"))
			folder += File.separator;
		int attempts = IPackager.maxAttemptsToCreateNewFile;
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

	public static String getTmpFileName(String infile, String suffix) throws Exception {
		File file = new File(infile);
		String folder = "";
		if (file.getParent() != null)
			folder = file.getAbsoluteFile().getParent();
		return getTmpFileName(folder, file.getName(), suffix);
	}

	public static File renameToNextSequencedFile(String srcfile) throws Exception {
		return renameToNextSequencedFile(srcfile, null, null, null);
	}
	
	private static String renameToNextSequencedFileLock = "renameToNextSequencedFile";
	public static File renameToNextSequencedFile(String srcfile, String destfolder, String prefix, String suffix) throws Exception {
		synchronized (renameToNextSequencedFileLock) {
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

	public static HashMap<String, String> getXmlInfo(String xml) throws Exception {
		HashMap<String, String> hash = new HashMap<String, String>();
		BufferedReader br = new BufferedReader(new FileReader(new File(xml)));
		XMLStreamReader reader = XMLInputFactory.newFactory().createXMLStreamReader(br);
		String key = null, val = null;
		while(reader.hasNext()) {
			switch(reader.getEventType()) {
			case XMLStreamConstants.START_ELEMENT:
				key = reader.getName().getLocalPart();
				val = null;
				break;
			case XMLStreamConstants.CHARACTERS:
				val = reader.getText();
				break;
			case XMLStreamConstants.END_ELEMENT:
				if (key != null && val != null && key.equals(reader.getName().getLocalPart())) {
					hash.put(key, val);
				}
				key = val = null;
				break;
			}
			reader.next();
		}
		reader.close();
		br.close();
		return hash;
	}
}
