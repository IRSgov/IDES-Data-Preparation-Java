package impl;

import impl.SignatureVerifier.SignatureInfo.ReferenceItem;
import intf.ISignatureVerifier;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.security.Key;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Stack;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLSignature.SignatureValue;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.namespace.QName;
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
import org.xml.sax.InputSource;

import util.UtilShared;
import util.UtilShared.XmlTag;

import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import com.sun.org.apache.xml.internal.security.utils.IgnoreAllErrorHandler;

/*
 * @author	Subir Paul (OS:IT:ES:EST:PA:S1)
 * 
 */
public class SignatureVerifier implements ISignatureVerifier {
	protected Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());
	
	// for debug only
	public byte[] digestBuf  = null;
	
	protected Boolean verificationFlag = true;
	
	protected class SignatureInfo {
		class ReferenceItem {
			String uri = null, transform = null, digestMethod = null, digestVal = null, calcDigestVal = null;

			@Override
			public String toString() {
				StringBuilder sb = new StringBuilder();
				sb.append("uri=");
				sb.append(uri);
				sb.append("; transform=");
				sb.append(transform);
				sb.append("; digestMethod=");
				sb.append(digestMethod);
				sb.append("; digestVal=");
				sb.append(digestVal);
				sb.append("; calcDigestVal=");
				sb.append(calcDigestVal);
				return sb.toString();
			}
		}
		
		class SignedInfoItem {
			String canonMethod = null, sigMethod = null, signedInfoStringToVerifySignature = null;
			List<ReferenceItem> references = new ArrayList<ReferenceItem>();

			@Override
			public String toString() {
				StringBuilder sb = new StringBuilder();
				sb.append("canonMethod=");
				sb.append(canonMethod);
				sb.append("; sigMethod=");
				sb.append(sigMethod);
				sb.append("; signedInfoStringToVerifySignature=");
				sb.append(signedInfoStringToVerifySignature);
				for (int i = 0; i < references.size(); i++) {
					sb.append("; ");
					sb.append(references.get(i));
				}
				return sb.toString();
			}
		}
		
		QName qname = null; //Signature element qname. <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		SignedInfoItem signedInfo = null;
		//Signature element nsuri http://www.w3.org/2000/09/xmldsig#
		String nsuri = null, signatureValue = null;
		//<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">, </ds:Signature">
		String sigStartElemToWrapXml = null, sigEndElemToWrapXml = null;
		PublicKey sigPublicKey = null;
		
		protected SignatureInfo(QName qname, PublicKey sigPublicKey) {
			this.qname = qname;
			this.sigPublicKey = sigPublicKey;
			nsuri = qname.getNamespaceURI();
			String prefix = qname.getPrefix();
			sigStartElemToWrapXml = "<" + ((prefix == null || "".equals(prefix)) ? "" : prefix + ":") + "Signature " + ((prefix == null || "".equals(prefix)) ? "xmlns" : "xmlns:" + prefix) + "=\"" + nsuri + "\">";
			sigEndElemToWrapXml = "</" + ((prefix == null || "".equals(prefix)) ? "" : prefix + ":") + "Signature>";
		}
		
		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			sb.append("qname=");
			sb.append(qname);
			sb.append("; nsuri=");
			sb.append(nsuri);
			sb.append("; sigPublicKey=");
			sb.append(sigPublicKey);
			return sb.toString();
		}

		protected boolean verifySignature() throws Exception {
			if (sigPublicKey == null || signedInfo == null || signedInfo.signedInfoStringToVerifySignature == null || signatureValue == null)
				throw new Exception("sigPublicKey == null || signedInfo == null || signedInfo.signedInfoStringToVerifySignature == null || signatureValue == null");
			Signature signature = Signature.getInstance(getAlgorithm(signedInfo.sigMethod));
			signature.initVerify(sigPublicKey);
			signature.update(signedInfo.signedInfoStringToVerifySignature.getBytes());
			boolean flag = signature.verify(Base64.decode(signatureValue.getBytes()));
			return flag;
		}
		
		protected void setSignatureValueFromXml(String xml, DocumentBuilder docBuilderNSTrue) throws Exception {
			xml = sigStartElemToWrapXml + xml + sigEndElemToWrapXml;
	        Document doc = docBuilderNSTrue.parse(new InputSource(new StringReader(xml)));
	        Element elem = doc.getDocumentElement();
	        String val = getElementVal(elem, nsuri, "SignatureValue");
	        if (val == null)
	        	throw new Exception("missing SignatureValue");
	        signatureValue = val.replace("\r", "").replace("\n", "");
		}
		
		protected void setSigPublicKeyFromXml(String xml, DocumentBuilder docBuilderNSTrue) throws Exception {
			xml = sigStartElemToWrapXml + xml + sigEndElemToWrapXml;
	        Document doc = docBuilderNSTrue.parse(new InputSource(new StringReader(xml)));
	        DOMStructure ds = new DOMStructure(doc.getDocumentElement().getFirstChild());
	        KeyInfo keyInfo = KeyInfoFactory.getInstance().unmarshalKeyInfo(ds);
			List<?> list = keyInfo.getContent();
			for (int i = 0; i < list.size(); i++) {
				XMLStructure xmlStructure = (XMLStructure) list.get(i);
				if (xmlStructure instanceof KeyValue) {
					try {
						sigPublicKey = ((KeyValue)xmlStructure).getPublicKey();
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
							sigPublicKey = cert.getPublicKey();
							break;
						}
					}
				}
			}
		}
		
		protected ReferenceItem getReference(String idAttr) {
			ReferenceItem ref = null;
			if (signedInfo != null && idAttr != null) {
				List<ReferenceItem> refs = signedInfo.references;
				for (int i = 0; i < refs.size(); i++) {
					ref = refs.get(i);
					if (idAttr.equals(ref.uri)) {
						return ref;
					}
				}
			}
			return null;
		}
		
		protected void setSignedInfoFromXml(String xml, DocumentBuilder docBuilderNSTrue) throws Exception {
			logger.trace("--> setSignedInfoFromXml(). xml=" + xml);
	        signedInfo = new SignedInfoItem();
			xml = sigStartElemToWrapXml + xml + sigEndElemToWrapXml;

	        Document doc = docBuilderNSTrue.parse(new InputSource(new StringReader(xml)));
	        Element docRootElem = doc.getDocumentElement();
	        
	        // check if indeed xml has SignedInfo tag
	        Node firstNode = docRootElem.getFirstChild();
	        if (!"SignedInfo".equals(firstNode.getLocalName()) || !nsuri.equals(firstNode.getNamespaceURI()))
	        	throw new Exception("XML does not seem to start with SignedInfo. XML=" + xml);
	        
	        signedInfo.canonMethod = getElementAttrVal(docRootElem, nsuri, "CanonicalizationMethod", "Algorithm");
	        signedInfo.sigMethod = getElementAttrVal(docRootElem, nsuri, "SignatureMethod", "Algorithm");
	        NodeList nl = docRootElem.getElementsByTagNameNS(nsuri, "Reference");
	        ReferenceItem ref;
	        Element elem;
	        for (int i = 0; i < nl.getLength(); i++) {
	        	elem = (Element)nl.item(i);
	        	ref = new ReferenceItem();
	        	signedInfo.references.add(ref);
	        	ref.uri = elem.getAttribute("URI");
	        	if (ref.uri.startsWith("#"))
	        		ref.uri = ref.uri.substring(1);
	        	ref.transform = getElementAttrVal(elem, nsuri, "Transform", "Algorithm");
	        	//if (ref.transform == null) ref.transform = CanonicalizationMethod.INCLUSIVE;
	        	ref.digestMethod = getElementAttrVal(elem, nsuri, "DigestMethod", "Algorithm");
	        	ref.digestVal = getElementVal(elem, nsuri, "DigestValue");
	        }
	        TransformerFactory transformerFactory = TransformerFactory.newInstance();
	        ByteArrayOutputStream baos = new ByteArrayOutputStream();
	        Transformer trans = transformerFactory.newTransformer();
	        trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
	        trans.transform(new DOMSource(docRootElem.getFirstChild()), new StreamResult(baos));
	        baos.close();
	        byte[] buf = baos.toByteArray();
	        
	        Canonicalizer canon = Canonicalizer.getInstance(signedInfo.canonMethod);
	        signedInfo.signedInfoStringToVerifySignature = new String(canon.canonicalize(buf));
			logger.trace("<-- setSignedInfoFromXml()");
		}
		
		protected boolean isDigestCalcFinished() {
			if (signedInfo == null || signedInfo.references == null)
				return false;
			ReferenceItem ref;
			for (int i = 0; i < signedInfo.references.size(); i++) {
				ref = signedInfo.references.get(i);
				if (ref.calcDigestVal == null)
					return false;
			}
			return true;
		}

		protected boolean isCalcDigestSameAsDocDigest() {
			if (signedInfo == null || signedInfo.references == null)
				return false;
			ReferenceItem ref;
			for (int i = 0; i < signedInfo.references.size(); i++) {
				ref = signedInfo.references.get(i);
				if (ref.calcDigestVal == null || ref.digestVal == null)
					return false;
				logger.debug("referenceURI=" + ref.uri);
				logger.debug("calcDigest  =" + ref.calcDigestVal);
				logger.debug("docDigest   =" + ref.digestVal);
				if (!ref.calcDigestVal.equals(ref.digestVal))
					return false;
			}
			return true;
		}
	}
	
	// An signed xml have one or multiple xml fragments signed, each identified by "Id" attribute at the start of fragment element 
	// There will be one <Reference> element with "URI" attribute matching xml fragment signed
	// This class contains info necessary to calculate digest of signed fragment to verify signature 
	protected class DynRefInfo {
		// use to calculate digest
		MessageDigest md = null;
		// transformation to apply to calculate digest - specified in <Transform> of corresponding <Reference>. ** Note ** We except max. 1 Transform. 
		Canonicalizer canon = null;
		ReferenceItem ref = null;
		QName qname = null;
		
		// We piggyback transformation to existing DOM based apis
		// As we are using streaming based apis to read partial xml and calculate digest after necessary transformation, 
		// we need to keep track start/end tags
		// Partial xml frags may not be in valid xml format (missing start/end tags) and we need to add missing start/end tags 
		// to form valid xml in order to apply transformation. 
		// These Stack vars are used keep track missing start/end tags of an xml frags 

		//start tag are pushed in stackStartTag and popped in matching end tags
		//start tags within a chunk are pushed in stackChunkStartTag and popped in matching end tags
		//contents of stackChunkStartTag are the tags defined in the chunk whose end tags not present in the chunk
		//while processing chunk, for each stackChunkStartTag elements, a end tag suffix is created
		//stackChunkEndTag contains end tags in chunk for missing start tag in chunk. 
		//while processing chunk, for each stackChunkEndTag elements, a start tag prefix is created
		Stack<XmlTag> stackStartTag = new Stack<XmlTag>(), stackChunkStartTag = new Stack<XmlTag>(), stackChunkEndTag = new Stack<XmlTag>();
		
		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			sb.append("qname=");
			sb.append(qname.toString());
			sb.append("; stackStartTag=");
			for (int i = 0; i < stackStartTag.size(); i++)
				sb.append(stackStartTag.get(i));
			sb.append("; stackChunkStartTag=");
			for (int i = 0; i < stackChunkStartTag.size(); i++)
				sb.append(stackChunkStartTag.get(i));
			sb.append("; stackChunkEndTag=");
			for (int i = 0; i < stackChunkEndTag.size(); i++)
				sb.append(stackChunkEndTag.get(i));
			return sb.toString();
		}
	}
	
	protected class KeyValueKeySelector extends KeySelector {
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
	
	public SignatureVerifier() {
		if (!Init.isInitialized())
			Init.init();
    }
    
	protected String getAlgorithm(String dsigAlgo) throws Exception {
		if (DigestMethod.SHA512.equals(dsigAlgo))
			return "SHA-512";
		if (DigestMethod.SHA256.equals(dsigAlgo))
			return "SHA-256";
		if (DigestMethod.SHA1.equals(dsigAlgo))
			return "SHA-1";
		if ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512".equals(dsigAlgo))
			return "SHA512withRSA";
		if ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".equals(dsigAlgo))
			return "SHA256withRSA";
		if ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384".equals(dsigAlgo))
			return "SHA384withRSA";
		if (SignatureMethod.DSA_SHA1.equals(dsigAlgo))
			return "SHA1withDSA";
		if (SignatureMethod.RSA_SHA1.equals(dsigAlgo))
			return "SHA1withRSA";
		throw new Exception(dsigAlgo + " not spported");
	}
	
	// gets start element. If start element happens to be the fragment signed, creates a new DynRefInfo which is used while calculating digest 
	protected DynRefInfo getStartElem(XMLStreamReader reader, StringBuilder sbElem, XmlTag lastStartTag, 
			SignatureInfo sigInfo) throws Exception {
		logger.trace("--> getStartElem()");
		DynRefInfo dynRefInfo = null;
		String prefix, localname, qnameS, nsuri, tmpS;
		int nscount, count;
		QName qname = reader.getName();
		prefix = reader.getPrefix();
		localname = reader.getLocalName();
		qnameS = ((prefix == null || "".equals(prefix)) ? "" : prefix + ":") + localname;
		sbElem.append('<');
	    sbElem.append(qnameS);
	    List<String> nsSortedList = null; String defaultNs = null; String[] nsSortedArr = null, attrSortedArr = null;
		count = reader.getAttributeCount();
		if (count > 0) {
			attrSortedArr = new String[count];
			for (int i = 0; i < count; i++) {
				tmpS = reader.getAttributeValue(i).replace("'", "&apos;").replace("\"", "&quot;");
				localname = reader.getAttributeLocalName(i);
				if ("Id".equals(localname) && sigInfo != null && sigInfo.signedInfo != null && qname.getNamespaceURI().equals(sigInfo.qname.getNamespaceURI())) {
					//<ds:KeyInfo Id="id-2e2baeca5b3e4cc566fdd2c7bef9cd8af9c6843a">, <ds:Object Id="id-7ad1eeaa7ef88e694a2769a80ff0722795f23bea">
					ReferenceItem ref = sigInfo.getReference(tmpS);
					if (ref != null) {
						dynRefInfo = new DynRefInfo();
						dynRefInfo.qname = qname;
						dynRefInfo.ref = ref;
						dynRefInfo.md = MessageDigest.getInstance(getAlgorithm(ref.digestMethod));
						if (ref.transform != null && !ref.transform.equals(CanonicalizationMethod.BASE64))
							dynRefInfo.canon = Canonicalizer.getInstance(ref.transform);
					}
				}
				prefix = reader.getAttributePrefix(i);
				attrSortedArr[i] = ((prefix == null || "".equals(prefix)) ? localname : (prefix + ":" + localname)) + "=\"" + tmpS + "\"";
			}
		}
		if (dynRefInfo != null) {
			// top signed xml frag element should have namespace inherited for digest calc  
			prefix = sigInfo.qname.getPrefix();
			nsuri = sigInfo.qname.getNamespaceURI();
			if (nsuri == null)
				nsuri = "";
			nsuri = "\"" + nsuri + "\"";
			tmpS = "xmlns";
			if (prefix != null && !"".equals(prefix))
				tmpS = tmpS + ":" + prefix;
			if ("xmlns".equals(tmpS)) {
				defaultNs = "xmlns=" + nsuri;
				lastStartTag.nsuri = defaultNs;
			}
			else {
				if (nsSortedList == null)
					nsSortedList = new ArrayList<String>();
				nsSortedList.add(tmpS + "=" + nsuri);
			}
		}
	    nscount = reader.getNamespaceCount();
		if (nscount > 0) {
			for (int i = 0; i < nscount; i++) {
				prefix = reader.getNamespacePrefix(i);
				nsuri = reader.getNamespaceURI(i);
				if (nsuri == null)
					nsuri = "";
				else
					nsuri = nsuri.replace("'", "&apos;").replace("\"", "&quot;");
				nsuri = "\"" + nsuri + "\"";
				tmpS = "xmlns";
				if (prefix != null && !"".equals(prefix))
					tmpS = tmpS + ":" + prefix;
				if ("xmlns".equals(tmpS)) {
					defaultNs = "xmlns=" + nsuri;
					lastStartTag.nsuri = defaultNs;
				}
				else {
					if (nsSortedList == null)
						nsSortedList = new ArrayList<String>();
					nsSortedList.add(tmpS + "=" + nsuri);
				}
			}
		}
		if (defaultNs != null) {
			sbElem.append(" ");
			sbElem.append(defaultNs);
		}
		if (nsSortedList != null) {
			nsSortedArr = nsSortedList.toArray(new String[0]);
			//probably sorted name spaces may not be needed as transformation (most likely) sort them anyway
			Arrays.sort(nsSortedArr);
			for (int i = 0; i < nsSortedArr.length; i++) {
				sbElem.append(" ");
				sbElem.append(nsSortedArr[i]);
				if ("".equals(lastStartTag.nsuri))
					lastStartTag.nsuri = nsSortedArr[i];
				else
					lastStartTag.nsuri = lastStartTag.nsuri + " " + nsSortedArr[i];
			}
		}
		if (attrSortedArr != null) {
			//probably sorted attributes may not be needed as transformation (most likely) sort them anyway
			Arrays.sort(attrSortedArr);
			for (int i = 0; i < attrSortedArr.length; i++) {
				sbElem.append(" ");
				sbElem.append(attrSortedArr[i]);
			}
		}
		sbElem.append(">");
		logger.trace("sbElem=" + sbElem.toString());
		logger.trace("<-- getStartElem()");
		return dynRefInfo;
	}
	
	protected String getElementVal(Element elem, String nsuri, String tagname) {
		NodeList nl = elem.getElementsByTagNameNS(nsuri, tagname);
		if (nl.getLength() > 0)
			return nl.item(0).getTextContent();
		return null;
	}
	
	protected String getElementAttrVal(Element elem, String nsuri, String tagname, String attrname) {
		NodeList nl = elem.getElementsByTagNameNS(nsuri, tagname);
		Node node;
		if (nl.getLength() > 0) {
			node = nl.item(0).getAttributes().getNamedItem(attrname);
			if (node != null)
				return node.getTextContent();
		}
		return null;
	}

	protected void updateDigest(StringBuilder parseBuf, DynRefInfo dynRefInfo, DocumentBuilder docBuilderNSTrue) throws Exception {
		logger.trace("--> updateDigest(). dynRefInfo=" + dynRefInfo.toString());
		try {
	    	if (dynRefInfo.canon != null)
	    		updateDigestWithXmlChunk(parseBuf, dynRefInfo, docBuilderNSTrue);
	    	else if (isBinaryContent(dynRefInfo)) {
	    		// base64 transformation used to sign binary file 
	    		String digestval = parseBuf.toString().replace("\r", "").replace("\n", "");
	    		//base64 decode string should be divisible by 4
	    		if (digestval.length() % 4 != 0)
	    			return;
	    		logger.trace("digestval=" + digestval);
	    		dynRefInfo.md.update(Base64.decode(digestval));
	    	}
	    	else // no <Transforms> in <SignedInfo>, possibly a signed text doc
	    		updateDigest(parseBuf, dynRefInfo);
	    	dynRefInfo.stackChunkStartTag.clear(); 
	    	dynRefInfo.stackChunkEndTag.clear();
	    	parseBuf.setLength(0);
		} catch(Exception e) {
			logger.debug("parseBuf=" + parseBuf.toString());
			logger.error(e.getMessage());
			throw e;
		}
		logger.trace("<-- updateDigest()");
	}
	
	protected void updateDigest(StringBuilder parseBuf, DynRefInfo dynRefInfo) throws Exception {
		String digestval = parseBuf.toString();
		//takes care TEXT signing (no transformation). \r is not allowed in xml so \r has been replaced with &#xD; for digest calc 
		digestval = digestval.replace("\r", "&#xD;");
		logger.trace("digestval=" + digestval);
		byte[] tmpbuf = digestval.getBytes();
		dynRefInfo.md.update(tmpbuf);
		if (digestBuf != null) 
			digestBuf = UtilShared.append(digestBuf, tmpbuf);
	}
	
	protected void updateDigestWithXmlChunk(StringBuilder parseBuf, DynRefInfo dynRefInfo, DocumentBuilder docBuilderNSTrue) throws Exception {
		logger.trace("--> updateDigestWithXmlChunk(). dynRefInfo=" + dynRefInfo);
		try {
			logger.trace("dynRefInfo=" + dynRefInfo);
	    	//stackChunkStartTag has start tags whose end tags are not in chunk
	    	//stackChunkEndTag has end tags whose start tags are not in chunk
	    	int startPrefixTagCount = 0, pos;
	    	String startPrefixTags = "", endSuffixTags = "", prefix, suffix;
	    	XmlTag tag;
	    	byte[] tmpbuf;
	    	int startTagToAddCount = dynRefInfo.stackStartTag.size() - dynRefInfo.stackChunkStartTag.size();
	    	//add end tags, newest to oldest to match xml structure, to xml chunk for transformation
	    	while (!dynRefInfo.stackChunkStartTag.empty()) {
	    		//stackChunkStartTag - 0=<MessageSpec>, 1=<TAG>....add suffix </TAG></MessageSpec>
	    		tag = dynRefInfo.stackChunkStartTag.pop();
	    		//corresponding start tag exists in chunk
	    		endSuffixTags = endSuffixTags + tag.getEndTag();
	    	}
	    	//add start tags, newest to oldest to match xml structure, to xml chunk for transformation
	    	while (!dynRefInfo.stackChunkEndTag.empty()) {
	    		//stackChunkEndTag - 0=<Address>, 1=<AddressFix>....meaning parseBuf has </AddressFix></Address>
	    		//add prefix <Address><AddressFix>
	    		startPrefixTagCount++;
	    		tag = dynRefInfo.stackChunkEndTag.pop();
	    		startPrefixTags = startPrefixTags + tag.getStartTag();
	    		//corresponding end tag exists in chunk
	    	}
	    	//add tags, prefix and suffix, present in stackStartTag as they may have NS defined
	    	//even if a tag in stackStartTag has no NS defined, we need them because of correct transformation, mainly for 'Exclusive' transformation 
	    	//stackStartTag - 0=<OUTERTAG>, 1=<MessageSpec>, 2=<TAG>, 3=<..>, stackChunkStartTag=<TAG>
	    	//....add prefix=<OUTERTAG><MessageSpec> and suffix=</MessageSpec></OUTERTAG>
	    	prefix = suffix = "";
	    	for (int i = 0; i < startTagToAddCount; i++) {
	    		tag = dynRefInfo.stackStartTag.get(i);
	    		//do not restrict to tags with ns only - Exclusive transformation would fail
				startPrefixTagCount++;
				prefix = prefix + tag.getStartTag();
				suffix = tag.getEndTag() + suffix;
	    	}
	    	startPrefixTags = prefix + startPrefixTags;
	    	endSuffixTags = endSuffixTags + suffix;

	    	logger.trace("parseBuf=" + parseBuf.toString());
	    	logger.trace("to transform str startPrefixTags=" + startPrefixTags);
	    	logger.trace("to transform str endSuffixTags  =" + endSuffixTags);
	    	String modifiedval = startPrefixTags + parseBuf.toString() + endSuffixTags;
	    	logger.trace("modifiedval    =" + modifiedval);
	    	Document doc = docBuilderNSTrue.parse(new InputSource(new StringReader(modifiedval)));
			String digestval = new String(dynRefInfo.canon.canonicalizeSubtree(doc));
			logger.trace("transformed str=" + digestval);
			//simply drop endSuffixTags - they don't gets altered by canonicalization
			if (endSuffixTags.length() > 0)
				digestval = digestval.substring(0, digestval.length() - endSuffixTags.length());
			//drop canonicalized startPrefixTags - remember they may be altered by transformation and so use prefix count to drop them
			pos = 0;
			for (int i = 0; i < startPrefixTagCount; i++)
				pos = digestval.indexOf(">", pos + 1);
			if (pos > 0)
				digestval = digestval.substring(pos + 1);
			logger.trace("digestval      =" + digestval);
			tmpbuf = digestval.getBytes();
			dynRefInfo.md.update(tmpbuf);
			if (digestBuf != null) 
				digestBuf = UtilShared.append(digestBuf, tmpbuf);
		} catch(Exception e) {
			logger.debug("parseBuf=" + parseBuf.toString());
			logger.debug("dynRefInfo=" + dynRefInfo.toString());
			logger.error(e.getMessage());
			throw e;
		}
		logger.trace("<-- updateDigestWithXmlChunk()");
	}

	// Verification with JDK DOM based api. Use for relatively small file as DOM reads entire doc in memory 
	protected boolean verifySignature(String signedFile, PublicKey sigkey, boolean useFakeElem) throws Exception  {
		logger.debug("--> verifySignature(). signedFile=" + signedFile + ", sigkey=" + sigkey + ", useFakeElem=" + useFakeElem);
		boolean ret = false;
		XMLSignatureFactory xmlSigFactory;
		XMLSignature signature;
		NodeList nl;
		DocumentBuilderFactory dbf;
		Document doc;
		DOMValidateContext valContext;
		boolean coreVerification, sigValVerification, refVerification;
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
			logger.trace("isFakeElem=" + isFakeElem);
			if (isFakeElem) {
				//very important - replace fakeobject with real one
				doc.getDocumentElement().replaceChild(objNode, fakeObjNode);
			}
	        signature = xmlSigFactory.unmarshalXMLSignature(valContext);
		    coreVerification = signature.validate(valContext);
			logger.debug("Signature core verification=" + coreVerification);
		    SignatureValue sigval = signature.getSignatureValue();
		    sigValVerification = sigval.validate(valContext);
		    logger.debug("SignatureValue varification status=" + sigValVerification);
	        iter = signature.getSignedInfo().getReferences().iterator();
	        Reference ref;
	        boolean refVerificationFlag = true;
	        for (int j=0; iter.hasNext(); j++) {
	        	ref = (Reference) iter.next();
	        	refVerification = ref.validate(valContext);
	        	logger.debug("ref["+j+"] verification status=" + refVerification);
	        	refVerificationFlag &= refVerification;
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
			ret = coreVerification & sigValVerification & refVerificationFlag;
		} catch (Exception e) {
			e.printStackTrace();
			//throw e; // do not throw
		} finally {
		}
		logger.debug("signature verification=" + ret);
		logger.debug("<-- verifySignature()");
		return ret;
	}
	
	protected boolean isBinaryContent(DynRefInfo dynRefInfo) {
		if (dynRefInfo != null && dynRefInfo.ref != null && dynRefInfo.ref.transform != null && dynRefInfo.ref.transform.equals(CanonicalizationMethod.BASE64))
			return true;
		return false;
	}
	
	protected void updateVerificationFlag(boolean flag) {
		synchronized (verificationFlag) {
			verificationFlag &= flag;
		}
	}
	
	// XML streaming based api to read xml, calculate/update digest of partial frags as it reads. Use this for large file. 
	public boolean verifySignatureStreaming(String signedXmlFile, PublicKey sigPublicKey) throws Exception {
		logger.debug("--> verifySignatureStreaming(). signedXmlFile=" + signedXmlFile + ", sigPublicKey=" + sigPublicKey);
		boolean success = false;
		XMLStreamReader reader = null;
		InputStream is = null;
		boolean finished = false;
		QName qname;;
		StringBuilder sbElem = new StringBuilder(), parseBuf = new StringBuilder();
		SignatureInfo sigInfo = null;
		int minChunkSize = UtilShared.defaultChunkStreamingSize;
		String qnameS, prefix, localname, tmpS;
		DynRefInfo dynRefInfo = null, tmpDynRefInfo = null;
		XmlTag tag, lastStartTag;
		//use chunk size for payload only which starts after Object tag
		boolean isObjectTagRead = false;
		try {
			if (digestBuf != null)
				digestBuf = new byte[0];
	    	DocumentBuilderFactory dbfNSTrue = DocumentBuilderFactory.newInstance();
	        dbfNSTrue.setNamespaceAware(true);
	        DocumentBuilder docBuilderNSTrue = dbfNSTrue.newDocumentBuilder();
	        docBuilderNSTrue.setErrorHandler(new IgnoreAllErrorHandler());
	        is = new FileInputStream(new File(signedXmlFile));
			reader = XMLInputFactory.newFactory().createXMLStreamReader(is);
			while(!finished) {
				sbElem.setLength(0);
				switch(reader.getEventType()) {
				case XMLStreamConstants.START_ELEMENT:
					qname = reader.getName();
					localname = qname.getLocalPart();
					lastStartTag = new XmlTag(qname);
					tmpDynRefInfo = getStartElem(reader, sbElem, lastStartTag, sigInfo);
					// it is unlikely that dynRefInfo != null and tmpDynRefInfo != null. But may happen in certain situation like if a signed xml is signed again
					if (dynRefInfo == null && tmpDynRefInfo != null) {
						dynRefInfo = tmpDynRefInfo;
						parseBuf.setLength(0);
					}
					// isObjectTagRead = true and encountered <Signature>/<SignedInfo>/<SignatureValue> may happen in certain situation like if a signed xml is signed again
					if (!isObjectTagRead && "Signature".equals(localname))
						sigInfo = new SignatureInfo(qname, sigPublicKey);
					else if (!isObjectTagRead && ("SignedInfo".equals(localname) || "SignatureValue".equals(localname)))
						parseBuf.setLength(0);
					else if (!isObjectTagRead && "Object".equals(localname))
						isObjectTagRead = true;
					// don't include <Object>, <SignatureProperty>, <SignaturePropertied> in BASE64 transformation digest calc
					if (!isBinaryContent(dynRefInfo))
						parseBuf.append(sbElem.toString());
					if (dynRefInfo != null) {
						dynRefInfo.stackStartTag.push(lastStartTag);
						dynRefInfo.stackChunkStartTag.push(lastStartTag);
					}
					break;
				case XMLStreamConstants.CHARACTERS:
					tmpS = reader.getText();
					//replace predefined xml entity [<, >, &] with escape sequence. note [', "] are not allowed in attribute only
					tmpS = tmpS.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
					parseBuf.append(tmpS);
					if (isObjectTagRead && dynRefInfo != null && parseBuf.length() > minChunkSize) 
			    		updateDigest(parseBuf, dynRefInfo, docBuilderNSTrue);
					break;
				case XMLStreamConstants.COMMENT:
					// do not deal with it now - revisit if necessary
					break;
				case XMLStreamConstants.END_ELEMENT:
				    qname = reader.getName();
					if (dynRefInfo != null && !dynRefInfo.stackStartTag.empty()) {
						tag = dynRefInfo.stackStartTag.pop();
					    if (dynRefInfo.stackChunkStartTag.empty())
					    	dynRefInfo.stackChunkEndTag.push(tag); //missing matching start tag in chunk so push tag in stackChunkEndTag
					    else
					    	dynRefInfo.stackChunkStartTag.pop(); //matching end tag found in chunk so pop tag from stackChunkStarttag
					}
					prefix = reader.getPrefix();
					localname = reader.getLocalName();
					qnameS = ((prefix == null || "".equals(prefix)) ? "" : prefix + ":") + localname;
					sbElem.append("</" + qnameS + ">");
					if (!isBinaryContent(dynRefInfo))
						parseBuf.append(sbElem.toString());
				    if (!isObjectTagRead && sigInfo != null && "SignedInfo".equals(localname)) {
				    	sigInfo.setSignedInfoFromXml(parseBuf.toString(), docBuilderNSTrue);
				    	parseBuf.setLength(0);
					} else if (!isObjectTagRead && sigInfo != null && "SignatureValue".equals(localname)) {
						sigInfo.setSignatureValueFromXml(parseBuf.toString(), docBuilderNSTrue);
						parseBuf.setLength(0);
					} else if (!isObjectTagRead && sigInfo != null && "KeyInfo".equals(localname) && sigInfo.sigPublicKey == null) {
						sigInfo.setSigPublicKeyFromXml(parseBuf.toString(), docBuilderNSTrue);
						//do not set parseBuf.setLength(0) as KeyInfo can be a Signature Reference xml frag
					}
				    if (dynRefInfo != null && dynRefInfo.stackStartTag.empty()) {
			    		updateDigest(parseBuf, dynRefInfo, docBuilderNSTrue);
				    	byte[] buf = dynRefInfo.md.digest();
				    	dynRefInfo.ref.calcDigestVal = Base64.encode(buf);
				    	logger.trace("calcDigestVal=" + dynRefInfo.ref.calcDigestVal);
				    	logger.trace("docDigestVal =" + dynRefInfo.ref.digestVal);
				    	if (dynRefInfo.ref.digestVal.equals(dynRefInfo.ref.calcDigestVal))
				    		logger.trace("Same Digest");
				    	dynRefInfo = null;
				    	finished = sigInfo.isDigestCalcFinished();
				    } else if (isObjectTagRead && dynRefInfo != null && parseBuf.length() > minChunkSize)
			    		updateDigest(parseBuf, dynRefInfo, docBuilderNSTrue);
				    break;
				case XMLStreamConstants.END_DOCUMENT:
					finished = true;
				    break;
				}
				if (reader.hasNext())
					reader.next();
				else if (!finished)
					throw new Exception("bug. no more element to reach while not end of document");
			}
			reader.close();
			is.close();
			reader = null;
			is = null;
			// check signature
			boolean digestVerificationFlag = sigInfo.isCalcDigestSameAsDocDigest();
			logger.debug("digestVerificationFlag=" + digestVerificationFlag);
			boolean sigValueVerificationFlag = sigInfo.verifySignature();
			logger.debug("sigValueVerificationFlag=" + sigValueVerificationFlag);
			success = digestVerificationFlag & sigValueVerificationFlag;
		} catch(Exception e) {
			e.printStackTrace();
			logger.error("infile=" + signedXmlFile + ", exception msg=" + e.getMessage());
			throw e;
		} finally {
			if (reader != null) try{reader.close();}catch(Exception e){}
			if (is != null) try{is.close();}catch(Exception e){}
		}
		logger.debug("signature verification=" + success);
		logger.debug("<-- verifySignatureStreaming()");
		updateVerificationFlag(success);
		return success;
	}
	
	public boolean verifySignatureStreaming(String signedXmlFile) throws Exception {
		boolean flag = verifySignatureStreaming(signedXmlFile, (PublicKey)null);
		updateVerificationFlag(flag);
		return flag;
	}
	
	public boolean verifySignatureStreaming(String signedXmlFile, X509Certificate sigCert) throws Exception {
		boolean flag = verifySignatureStreaming(signedXmlFile, sigCert.getPublicKey());
		updateVerificationFlag(flag);
		return flag;
	}
	
	public boolean verifySignature(String signedXmlFile) throws Exception  {
		boolean flag = verifySignature(signedXmlFile, (PublicKey)null);
		updateVerificationFlag(flag);
		return flag;
	}
	
	public boolean verifySignature(String signedFile, PublicKey sigPublicKey) throws Exception  {
		boolean flag = verifySignature(signedFile, sigPublicKey, true);
		updateVerificationFlag(flag);
		return flag;
	}
	
	public boolean verifySignature(String signedXmlFile, X509Certificate sigCert) throws Exception {
		boolean flag = verifySignature(signedXmlFile, sigCert.getPublicKey());
		updateVerificationFlag(flag);
		return flag;
	}

	public boolean getVerificationFlag() {
		synchronized (verificationFlag) {
			return verificationFlag;
		}
	}
}
