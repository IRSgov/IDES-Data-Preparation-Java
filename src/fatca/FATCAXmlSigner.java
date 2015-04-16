package fatca;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import com.sun.org.apache.xml.internal.security.utils.IgnoreAllErrorHandler;

public class FATCAXmlSigner {
	public static String SIGNATURE_OBJECT_ID = "FATCA";
	public static String SIGNATUER_ALGO = "SHA256withRSA";
	public static String MESSAGE_DIGEST_ALGO = "SHA-256";
	public static String SIGNATURE_DIGEST_METHOD = DigestMethod.SHA256;
	public static String SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
	public static String CANONICALIZATION_METHOD = CanonicalizationMethod.INCLUSIVE;
	
	public static int bufSize = 64 * 1024;

	protected static Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());
	protected static int logLevel = logger.getEffectiveLevel().toInt();
	protected static String digprefix = "<Object xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"" + SIGNATURE_OBJECT_ID + "\">";
	protected static String digsuffix = "</Object>";
	protected static final int STARTTAG = 0;
	protected static final int ENDTAG = 1;
	protected static final int CHUNK = 2;
	
	// for debug
	public StringBuilder digestBuf  = null;

	protected XMLSignatureFactory xmlSigFactory = null;
	protected KeyInfoFactory keyInfoFactory = null;
	protected TransformerFactory transformerFactory = null;
	protected SAXParserFactory saxFactory = null;  
	protected Canonicalizer canonicalizer =  null;
	protected DocumentBuilder docBuilder = null;
        
	protected String digestValue = null, signatureValue = null;
	protected MessageDigest messageDigest = null;
	protected ArrayList<String> nsStartTagList = new ArrayList<String>();
	protected ArrayList<String> nsEndTagList = new ArrayList<String>();

    public FATCAXmlSigner() {
    	try {
    		Init.init();
    		transformerFactory = TransformerFactory.newInstance();
    		saxFactory = SAXParserFactory.newInstance();  
    		xmlSigFactory = XMLSignatureFactory.getInstance();
            keyInfoFactory = xmlSigFactory.getKeyInfoFactory();
            saxFactory.setNamespaceAware(false);
            canonicalizer = Canonicalizer.getInstance(CANONICALIZATION_METHOD);
            DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
            dfactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
            dfactory.setNamespaceAware(true);
            dfactory.setValidating(true);
            docBuilder = dfactory.newDocumentBuilder();
            docBuilder.setErrorHandler(new IgnoreAllErrorHandler());
    	} catch(Exception e) {
    		logger.error(e.getMessage(), e);
    		throw new RuntimeException(e);
    	}
    }
    
    protected void initMessageDigest() throws NoSuchAlgorithmException {
		logger.debug("--> initMessageDigest()");
		digestValue = null;
    	messageDigest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGO);
		messageDigest.update(digprefix.getBytes());
		if (logLevel <= Level.DEBUG_INT && digestBuf != null) {
    		digestBuf.setLength(0);
    		digestBuf.append(digprefix);
    	}
		logger.debug("<-- initMessageDigest()");
    }
    
    protected void finalizeMessageDigest() {
		logger.debug("--> finalizeMessageDigest()");
		messageDigest.update(digsuffix.getBytes());
		digestValue = Base64.encode(messageDigest.digest());
		if (logLevel <= Level.DEBUG_INT && digestBuf != null)
    		digestBuf.append(digsuffix);
		logger.debug("<-- finalizeMessageDigest()");
    }

	protected void calcMsgDigestByParsingDoc(String infile) throws Exception {
		throw new Exception ("not yet implemented");
	}
	
    protected void calcMsgDigestNoTransformation(String xmlInputFile) throws Exception {
		logger.debug("--> calcMsgDigestNoTransformation(). xmlInputFile=" + xmlInputFile);
		int len;
		String tmp;
		initMessageDigest();
    	BufferedInputStream bis = new BufferedInputStream(new FileInputStream(xmlInputFile));
		boolean flag = true;
		byte[] tmpBuf = new byte[bufSize];
		while((len = bis.read(tmpBuf)) != -1) {
			tmp = new String(tmpBuf, 0, len);
			tmp = tmp.replace("\r", "");
			if (flag) {
				flag = false;
				if (tmp.startsWith("<?xml")) {
					int pos = tmp.indexOf(">");
					if (pos != -1) {
						tmp = tmp.substring(pos+1);
						if (tmp.startsWith("\n"))
							tmp = tmp.substring(1);
					}
				}
			}
    		if (logLevel <= Level.DEBUG_INT && digestBuf != null)
				digestBuf.append(tmp);
			messageDigest.update(tmp.getBytes());
		}
		bis.close();
		finalizeMessageDigest();
		logger.debug("<-- calcMsgDigestNoTransformation()");
    }
    
    protected Document createSignedDoc(boolean isTransformed, PrivateKey signatureKey, X509Certificate signaturePublicCert) throws Exception {
    	return createSignedDoc(null, isTransformed, signatureKey, signaturePublicCert);
    }

   protected Document createSignedDoc(String xmlInputFile, boolean isTransformed, PrivateKey signatureKey, X509Certificate signaturePublicCert) throws Exception {
		logger.debug("--> createSignedDoc(). xmlInputFile=" + xmlInputFile);
    	BufferedInputStream bis = null;
        Document doc = null;
    	try {
            String uri = "";
            Reference sigref;
            Node node;
        	if (xmlInputFile != null) {
            	bis = new BufferedInputStream(new FileInputStream(xmlInputFile));
    	        doc = docBuilder.parse(bis);
    	        node = doc.getDocumentElement();
        	}
        	else {
        		doc = docBuilder.newDocument();
            	node = doc.createTextNode("text");
        	}
        	XMLStructure content = new DOMStructure(node);
            XMLObject xmlobj = xmlSigFactory.newXMLObject
            	(Collections.singletonList(content), SIGNATURE_OBJECT_ID, null, null);
        	List<XMLObject> xmlObjs = Collections.singletonList(xmlobj);
        	if (!"".equals(SIGNATURE_OBJECT_ID))
        		uri = "#" + SIGNATURE_OBJECT_ID;
	        if (isTransformed)
	        	sigref = xmlSigFactory.newReference(uri, xmlSigFactory.newDigestMethod(SIGNATURE_DIGEST_METHOD, null), 
	        			Collections.singletonList(xmlSigFactory.newTransform(CANONICALIZATION_METHOD, 
	        					(TransformParameterSpec) null)), null, null);
	        else
	        	sigref = xmlSigFactory.newReference(uri, xmlSigFactory.newDigestMethod(SIGNATURE_DIGEST_METHOD, null), null, null, null);
            SignedInfo signedInfo = xmlSigFactory.newSignedInfo(
            		xmlSigFactory.newCanonicalizationMethod(CANONICALIZATION_METHOD, (C14NMethodParameterSpec) null),
            		xmlSigFactory.newSignatureMethod(SIGNATURE_METHOD, null),
            		Collections.singletonList(sigref));
            KeyInfo keyInfo = null;
            if (signaturePublicCert != null) {
	            List<X509Certificate> list = new ArrayList<X509Certificate>();
	            list.add(signaturePublicCert);
	            X509Data kv = keyInfoFactory.newX509Data(list);
	            keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(kv));
            }
            XMLSignature signature = xmlSigFactory.newXMLSignature(signedInfo, keyInfo, xmlObjs, null, null);
            DOMSignContext dsc = new DOMSignContext(signatureKey, doc);
            signature.sign(dsc);
    	} catch(Exception e) {
    		logger.error(e.getMessage(), e);
    		throw e;
    	} finally {
    		if (bis != null) try{bis.close();}catch(Exception e){}
    	}
		logger.debug("<-- createSignedDoc()");
    	return doc;
    }
    
    protected boolean signXML(String xmlInputFile, String signedXmlOutputFile, boolean transformXml, PrivateKey signatureKey, X509Certificate signaturePublicCert) throws Exception {
		logger.debug("--> signXML(). xmlInputFile=" + xmlInputFile + ", signedXmlOutputFile=" + signedXmlOutputFile + ", transformXml=" + transformXml);
    	boolean ret = false;
        ByteArrayOutputStream baos = null;
        BufferedOutputStream bos = null;
        BufferedInputStream bis = null;
    	try {
    		Node node;
    		Transformer trans;
    		NodeList nodeList;
    		boolean isTransformed = false;
            if (transformXml) {
	            logger.debug("parsing xml...." + new Date());
	            calcMsgDigestByParsingDoc(xmlInputFile);
	            isTransformed = true;
	    		logger.debug("parsing xml....done. " + new Date());
    		} else
    			calcMsgDigestNoTransformation(xmlInputFile);
            Document doc = createSignedDoc(isTransformed, signatureKey, signaturePublicCert);
    		nodeList = doc.getElementsByTagName("DigestValue");
            if (nodeList.getLength() > 0) {
            	node = nodeList.item(0);
            	node = node.getFirstChild();
            	node.setNodeValue(digestValue);
            } else
            	throw new Exception("Invalid document structure. Missing <DigestValue> content");
            signatureValue = null;
            nodeList = doc.getElementsByTagName("SignedInfo");
            if (nodeList.getLength() > 0) {
            	node = nodeList.item(0); 
                baos = new ByteArrayOutputStream();
                trans = transformerFactory.newTransformer();
                trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
                trans.transform(new DOMSource(node), new StreamResult(baos));
                baos.close();
                if (!Init.isInitialized())
                	Init.init();
                Canonicalizer canon = Canonicalizer.getInstance(CANONICALIZATION_METHOD);
				Signature signature = Signature.getInstance(SIGNATUER_ALGO);
				signature.initSign(signatureKey);
				signature.update(canon.canonicalize(baos.toByteArray()));
				byte[] signatureBuf = signature.sign();
    			signatureValue = Base64.encode(signatureBuf);
    			baos = null;
            } else
            	throw new Exception("Invalid document structure. Missing <SignedInfo> content");
            nodeList = doc.getElementsByTagName("SignatureValue");
            if (nodeList.getLength() > 0)
            	nodeList.item(0).getFirstChild().setNodeValue(signatureValue);
            else
            	throw new Exception("Invalid document structure. Missing <SignatureValue> content");
            String textContent = null;
    		nodeList = doc.getElementsByTagName("Object");
            if (nodeList.getLength() > 0) {
            	node = nodeList.item(0);
            	node = node.getFirstChild();
            	textContent = node.getTextContent();
            } else
            	throw new Exception("Invalid document structure. Missing <Object> content");
    		baos = new ByteArrayOutputStream();
            trans = transformerFactory.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(baos));
            baos.close();
            String tmp = baos.toString();
            baos = null;
            int pos = tmp.indexOf(textContent);
            if (pos == -1)
            	throw new Exception("Invalid document structure or invalid transformation");
            String prefix = tmp.substring(0, pos);
            String suffix = tmp.substring(pos + textContent.length());
            bos = new BufferedOutputStream(new FileOutputStream(signedXmlOutputFile));
            bos.write(prefix.getBytes());
            bis = new BufferedInputStream(new FileInputStream(xmlInputFile));
            int len;
            boolean flag = true;
            byte[] tmpBuf = new byte[bufSize];
            while((len = bis.read(tmpBuf)) != -1) {
				if (flag) {
					tmp = new String(tmpBuf, 0, len);
					flag = false;
					if (tmp.startsWith("<?xml")) {
						pos = tmp.indexOf(">");
						if (pos != -1) {
							tmp = tmp.substring(pos+1);
							if (tmp.startsWith("\r\n"))
								tmp = tmp.substring(2);
							if (tmp.startsWith("\n"))
								tmp = tmp.substring(1);
							if (tmp.startsWith("\r"))
								tmp = tmp.substring(1);
						}
					}
					bos.write(tmp.getBytes());
				} else 
					bos.write(tmpBuf, 0, len);
            }
        	bos.write(suffix.getBytes());
        	ret = true;
    	} catch(Exception e) {
    		logger.error(e.getMessage(), e);
    		throw e;
    	} finally {
    		if (bos != null) try{bos.close();}catch(Exception e){}
    		if (bis != null) try{bis.close();}catch(Exception e){}
    		if (baos != null) try{baos.close();}catch(Exception e){}
    	}
    	logger.debug("<--signXML()");
    	return ret;
    }

    protected void printNode(Node node) {
		logger.debug("--> printNode() " + node.getNodeName());
		logger.debug("prefix=" + node.getPrefix() + ", baseuri=" + 
				node.getBaseURI() + ", nsuri=" + node.getNamespaceURI() + ", value=" + node.getNodeValue());
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
	
    public void signDOM(String xmlInputFile, String signedXmlOutputFile, PrivateKey signatureKey, X509Certificate signaturePublicKey) throws Exception {
		logger.debug("--> signDOM(). xmlInputFile=" + xmlInputFile + ", signedXmlOutputFile=" + signedXmlOutputFile);
		BufferedOutputStream bos = null;
    	try {
	    	Document doc = createSignedDoc(xmlInputFile, true, signatureKey, signaturePublicKey);
	    	NodeList nodeList = doc.getElementsByTagName("DigestValue");
	        if (nodeList.getLength() > 0)
	        	digestValue = nodeList.item(0).getFirstChild().getNodeValue();
	    	nodeList = doc.getElementsByTagName("SignatureValue");
	        if (nodeList.getLength() > 0)
	        	signatureValue = nodeList.item(0).getFirstChild().getNodeValue();
	    	bos = new BufferedOutputStream(new FileOutputStream(signedXmlOutputFile));
	    	Transformer transformer = transformerFactory.newTransformer();
	        transformer.transform(new DOMSource(doc), new StreamResult(bos));
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
		} finally {
			if (bos != null) try{bos.close();}catch(Exception e) {}
		}
		logger.debug("<-- signDOM()");
    }
    
    public boolean signStreaming(String xmlInputFile, String signedXmlOutputFile, PrivateKey signatureKey, X509Certificate signaturePublicCert) throws Exception {
		logger.debug("--> signStreaming(). xmlInputFile=" + xmlInputFile + ", signedXmlOutputFile=" + signedXmlOutputFile);
    	boolean flag = signXML(xmlInputFile, signedXmlOutputFile, false, signatureKey, signaturePublicCert);
		logger.debug("<-- signStreaming()");
    	return flag;
    }
    
    public boolean signStreamingWithCanonicalization(String xmlInputFile, String signedXmlOutputFile, PrivateKey signatureKey, X509Certificate signaturePublicCert) throws Exception {
		logger.debug("--> signStreamingWithCanonicalization(). xmlInputFile=" + xmlInputFile + ", signedXmlOutputFile=" + signedXmlOutputFile);
    	boolean flag = signXML(xmlInputFile, signedXmlOutputFile, true, signatureKey, signaturePublicCert);
		logger.debug("<-- signStreamingWithCanonicalization()");
		return flag;
    }
}
