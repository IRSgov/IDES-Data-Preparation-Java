package fatca;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLSignature.SignatureValue;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.sun.org.apache.xml.internal.security.utils.Base64;

public class UtilShared {
	protected static Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

	public static String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";
	public static String RSA_TRANSFORMATION = "RSA";
	
	public static String SECRET_KEY_ALGO = "AES";
	public static int SECRET_KEY_SIZE = 256;
	
	public static String KEYSTORE_TYPE = "pkcs12";
	public static String CERTIFICATE_TYPE = "X.509";
	
	public static String genRandomId() {
		UUID uuid = UUID.randomUUID();
		return uuid + "@" + System.identityHashCode(uuid);
	}
	public static X509Certificate getCert(String keystorefile, String keystorepwd) throws Exception {
		return getCert(KEYSTORE_TYPE, keystorefile, keystorepwd, null);
	}
	
	public static X509Certificate getCert(String keystorefile, String keystorepwd, String alias) throws Exception {
		return getCert(KEYSTORE_TYPE, keystorefile, keystorepwd, alias);
	}
	
	public static X509Certificate getCert(String keystoretype, String keystorefile, String keystorepwd, String alias) throws Exception {
		try {
			//KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			KeyStore keystore = KeyStore.getInstance(keystoretype);
			FileInputStream fis = new FileInputStream(keystorefile);
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
			logger.error(e.getMessage(), e);
			throw e;
		}
		return null;
	}
	public static PrivateKey getPrivateKey(String keystorefile, String keystorepwd, String keypwd, String alias) throws Exception {
		return getPrivateKey(KEYSTORE_TYPE, keystorefile, keystorepwd, keypwd, alias);
	}
	
	public static PrivateKey getPrivateKey(String keystorefile, String keystorepwd, String keypwd) throws Exception {
		return getPrivateKey(KEYSTORE_TYPE, keystorefile, keystorepwd, keypwd, null);
	}
	
	public static PrivateKey getPrivateKey(String keystoretype, String keystorefile, String keystorepwd, String keypwd, String alias) throws Exception {
		try {
			//KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			KeyStore keystore = KeyStore.getInstance(keystoretype);
			FileInputStream fis = new FileInputStream(keystorefile);
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
			logger.error(e.getMessage(), e);
			throw e;
		}
		return null;
	}

	public static boolean verifySignatureDOM(String signedPlainTextFile, PublicKey sigkey) throws Exception  {
		logger.debug("--> verifySignatureDOM()");
		boolean ret = false;
		XMLSignatureFactory xmlsigfac;
		XMLSignature signature;
		NodeList nl;
		DocumentBuilderFactory dbf;
		Document doc;
		DOMValidateContext valContext;
		boolean coreValidity, sv, refValid;
		Iterator<?> iter;
		try {
			xmlsigfac = XMLSignatureFactory.getInstance();
			
		    dbf = DocumentBuilderFactory.newInstance();
	        dbf.setNamespaceAware(true);
	        DocumentBuilder db = dbf.newDocumentBuilder();
	        
	        doc = db.parse(new File(signedPlainTextFile));
	        nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Object");
			if (nl.getLength() == 0)
			    throw new Exception("Cannot find Object element");
			Node objNode = nl.item(0);
	    
	        String id = "";
	        Node attrId = objNode.getAttributes().getNamedItem("Id");
	        if (attrId  != null)
	        	id = attrId.getTextContent();
			Element fakeObjNode = doc.createElementNS(XMLSignature.XMLNS, "Object");
			fakeObjNode.setAttribute("Id", id);
			doc.getDocumentElement().replaceChild(fakeObjNode, objNode);
	    	nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
			if (nl.getLength() == 0) {
			    throw new Exception("Cannot find Signature element");
			}
			Node sigNode = nl.item(0);

			valContext = new DOMValidateContext(sigkey, sigNode);

	        //very important
	        doc.getDocumentElement().replaceChild(objNode, fakeObjNode);
			signature = xmlsigfac.unmarshalXMLSignature(valContext);
			coreValidity = signature.validate(valContext);
			 
			logger.debug("Signature core validation " + coreValidity);
			//if (coreValidity == false) {
			    SignatureValue sigval = signature.getSignatureValue();
			    sv = sigval.validate(valContext);
			    logger.debug("SignatureValue validation status: " + sv);
			    //if (sv == false) {
			        // Check the validation status of each Reference.
			        iter = signature.getSignedInfo().getReferences().iterator();
			        Reference ref;
			        for (int j=0; iter.hasNext(); j++) {
			        	ref = (Reference) iter.next();
			        	refValid = ref.validate(valContext);
			        	logger.debug("ref["+j+"] validity status: " + refValid);
			        	logger.debug("ref.getURI()=" + ref.getURI());
			        	logger.debug("ref.getCalculatedDigestValue()=" + Base64.encode(ref.getCalculatedDigestValue()));
			        	logger.debug("ref.getDigestValue()=" + Base64.encode(ref.getDigestValue()));
			        	List<?> lt = ref.getTransforms();
			        	Transform tr;
			        	for (int i = 0; i < lt.size(); i++) {
			        		tr = (Transform)lt.get(i);
			        		logger.debug("transform.getAlgorithm()=" + tr.getAlgorithm());
			        	}
			        }
			    //}
			//}
			ret = coreValidity;
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		} finally {
		}
		logger.debug("<-- verifySignatureDOM()");
		return ret;
	}
}
