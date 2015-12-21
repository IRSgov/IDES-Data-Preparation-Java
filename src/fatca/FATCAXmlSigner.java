package fatca;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Stack;
import java.util.UUID;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
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
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import com.sun.org.apache.xml.internal.security.utils.IgnoreAllErrorHandler;

/*
 * @author	Subir Paul (IT:ES:SE:PE)
 * 
 */
public class FATCAXmlSigner {
	public static Provider defaultSignatureFactoryProvider = null;

	protected String SIGNATURE_REF_ID = "FATCA";
	protected String SIGNATURE_ID = "SignatureId";
	protected String SIGNATUER_ALGO = "SHA256withRSA";
	protected String MESSAGE_DIGEST_ALGO = "SHA-256";
	protected String SIGNATURE_DIGEST_METHOD = DigestMethod.SHA256;
	protected String SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
	protected Provider defaultSignatureProvider = null;
	protected Provider defaultMessageDigestProvider = null;
	
	public enum SigRefIdPos {Object, SignatureProperty, SignatureProperties}
	public enum SigXmlTransform {Inclusive, InclusiveWithComments, Exclusive, ExclusiveWithComments, None};
	
	public enum SigDocType {XML, WRAPPEDXML, 
		TEXT,	// not used in FATCA
 		BINARY	// not used in FATCA
	};

	protected Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());
	protected final int STARTTAG = 0;
	protected final int ENDTAG = 1;
	protected final int CHAR = 2;
	protected int defaultBufSize = 8 * 1024;
	protected int defaultChunkStreamingSize = 8 * 1024;
	protected MyThreadSafeData myThreadSafeData = new MyThreadSafeData();
	
	private String uuid = UUID.randomUUID().toString().replace("-", "");
	
	// for debug only
	public StringBuilder digestBuf  = null;
	public boolean isValidateAllSignature = false;
	public Boolean isValidationSuccess = true;

	private class MyThreadSafeData {
		private String signaturePrefix = "";
		private Boolean useXmlChunkStreaming = true;
		private Integer bufSize = defaultBufSize;
		private Integer xmlChunkStreamingSize = defaultChunkStreamingSize;
		public int getXmlChunkStreamingSize() {
	    	synchronized (xmlChunkStreamingSize) {
				return xmlChunkStreamingSize;
			}
		}
		public void setXmlChunkStreamingSize(int val) {
	    	synchronized (xmlChunkStreamingSize) {
	    		xmlChunkStreamingSize = val;
	    	}
		}
		public int getBufSize() {
			synchronized (bufSize) {
				return bufSize;
			}
		}
		public void setBufSize(int val) {
			synchronized (bufSize) {
				bufSize = val;
			}
		}
		protected boolean isXmlChunkStreaming() {
	    	synchronized (useXmlChunkStreaming) {
	        	return useXmlChunkStreaming;
			}
	    }
	    protected void setXmlChunkStreaming(boolean val) {
	    	synchronized (useXmlChunkStreaming) {
	        	useXmlChunkStreaming = val;
			}
	    }
		protected void setSignaturePrefix(String prefix) {
	    	synchronized (signaturePrefix) {
	        	if (prefix == null)
	        		signaturePrefix = "";
	        	else
	        		signaturePrefix = prefix; 
			}
	    }
	    protected String getSignaturePrefix() {
	    	synchronized (signaturePrefix) {
	        	return signaturePrefix;
			}
	    }
	}

	public FATCAXmlSigner() {
		if (!Init.isInitialized())
			Init.init();
    }
    
    protected void processXmlFrag(int type, String tag, String val, MessageDigest messageDigest, Canonicalizer canonicalizer, 
    		DocumentBuilder docBuilderNSTrue, String wrapperPrefix, String wrapperNSUri) throws Exception {
		logger.trace("--> processXmlFrag(). type=" + type + ", tag=" + tag + ", val=" + val);
		Document doc;
		String addedStartTag = "", addedEndTag = "", modifiedval = val;
		if (type == STARTTAG)
			addedEndTag = "</" + tag + ">";
		else if (type == ENDTAG)
			addedStartTag = "<" + tag + ">";
		String fakeStartElem = "", fakeEndElem = "";
		String wrapperNS = wrapperPrefix==null?(wrapperNSUri==null?null:"xmlns=\""+wrapperNSUri+"\""):(wrapperNSUri==null?null:"xmlns:"+wrapperPrefix+"=\""+wrapperNSUri+"\"");
		if (wrapperNS != null || type == CHAR) {
			fakeStartElem = "<fake" + uuid;
			fakeEndElem = "</fake" + uuid;
			if (wrapperNS != null)
				fakeStartElem += " " + wrapperNS;
			fakeStartElem += ">";
			fakeEndElem += ">";
		}
		addedStartTag = fakeStartElem + addedStartTag;
		addedEndTag = addedEndTag + fakeEndElem;
		modifiedval = addedStartTag + val + addedEndTag;
		logger.trace("modifiedval=" + modifiedval);
		String digestval = null;
		try {
			doc = docBuilderNSTrue.parse(new InputSource(new StringReader(modifiedval)));
		} catch(Throwable e) {
			e.printStackTrace();
			//************* should not ever come here - investigate if it does ************** 
	    	DocumentBuilderFactory dbfNSFalse = DocumentBuilderFactory.newInstance();
	    	dbfNSFalse.setNamespaceAware(true);
    		DocumentBuilder docBuilderNSFalse = dbfNSFalse.newDocumentBuilder();
			docBuilderNSFalse.setErrorHandler(new IgnoreAllErrorHandler());
			doc = docBuilderNSFalse.parse(new InputSource(new StringReader(modifiedval)));
		}
		digestval = new String(canonicalizer.canonicalizeSubtree(doc));
		digestval = digestval.replace(addedStartTag, "").replace(addedEndTag, "");
		logger.trace("digestval=" + digestval);
		messageDigest.update(digestval.getBytes());
		if (digestBuf != null)
			digestBuf.append(digestval);
		logger.trace("<-- processXmlFrag()");
    }
    
	protected void writeBase64BinaryAndOptionallyCalcMsgDigest(String infile, String newline, OutputStream os, 
			boolean isCalcDigest, MessageDigest messageDigest) throws Exception {
		logger.debug("--> writeBase64BinaryAndOptionallyCalcMsgDigest(). infile=" + infile);
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(new File(infile)));
		if (isCalcDigest && messageDigest == null)
			throw new Exception("messageDigest must not be null if isCalcDigest=true");
		int len, offset = 0, nextoffset, lastlinelen = 0;
		byte[] buf = new byte[myThreadSafeData.getBufSize()];
		byte[] tmpBuf;
		while((len = bis.read(buf, offset, buf.length - offset)) != -1) {
			if (isCalcDigest)
				messageDigest.update(buf, offset, len);
			nextoffset = (offset+len) % 3;
			tmpBuf = new byte[offset+len-nextoffset];
			System.arraycopy(buf, 0, tmpBuf, 0, offset+len-nextoffset);
			for (int i = 0; i < nextoffset; i++)
				buf[i] = buf[offset+len-nextoffset+i];
			offset = nextoffset;
			lastlinelen = writeEncodedBinary(lastlinelen, tmpBuf, newline, os);
		}
		if (offset > 0) {
			tmpBuf = new byte[offset];
			System.arraycopy(buf, 0, tmpBuf, 0, offset);
			writeEncodedBinary(lastlinelen, tmpBuf, newline, os);
		}
		bis.close();
		logger.debug("<-- writeBase64BinaryAndOptionallyCalcMsgDigest()");
	}
	
	protected String getCanonicalizationMethod(SigXmlTransform xmlTransform) {
		if (xmlTransform == null)
			return CanonicalizationMethod.INCLUSIVE;
        switch(xmlTransform) {
        case InclusiveWithComments:
        	return CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS;
        case Exclusive:
        	return CanonicalizationMethod.EXCLUSIVE;
        case ExclusiveWithComments:
        	return CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS;
        case Inclusive:
        case None:
        default:
        	return CanonicalizationMethod.INCLUSIVE;
        }
	}
	
	protected byte[][] getSigRefIdPosTags(SigRefIdPos sigRefIdPos) {
		if (sigRefIdPos == null)
			sigRefIdPos = SigRefIdPos.Object;
    	byte[][] tags = new byte[2][];
    	String prefix = myThreadSafeData.getSignaturePrefix();
		switch(sigRefIdPos) {
		case SignatureProperties:
	    	if ("".equals(prefix)) {
	    		tags[0] = ("<SignatureProperties xmlns=\"" + XMLSignature.XMLNS + "\" Id=\"" + SIGNATURE_REF_ID + "\"><SignatureProperty Target=\"#" + SIGNATURE_ID + "\">").getBytes();
	    		tags[1] = "</SignatureProperty></SignatureProperties>".getBytes();
	    	} else {
	    		tags[0] = ("<" + prefix + ":SignatureProperties xmlns" + ":" + prefix + "=\"" + XMLSignature.XMLNS + "\" Id=\"" + SIGNATURE_REF_ID  + "\"><" + prefix + ":SignatureProperty Target=\"#" + SIGNATURE_ID + "\">").getBytes(); 
	    		tags[1] = ("</" + prefix + ":SignatureProperty></" + prefix + ":SignatureProperties>").getBytes();
	    	}
			break;
		case SignatureProperty:
	    	if ("".equals(prefix)) {
	    		tags[0] = ("<SignatureProperty xmlns=\"" + XMLSignature.XMLNS + "\" Id=\"" + SIGNATURE_REF_ID + "\" Target=\"#" + SIGNATURE_ID + "\">").getBytes();
	    		tags[1] = "</SignatureProperty>".getBytes();
	    	} else {
	    		tags[0] = ("<" + prefix + ":SignatureProperty xmlns" + ":" + prefix + "=\"" + XMLSignature.XMLNS + "\" Id=\"" + SIGNATURE_REF_ID  + "\" Target=\"#" + SIGNATURE_ID + "\">").getBytes(); 
	    		tags[1] = ("</" + prefix + ":SignatureProperty>").getBytes();
	    	}
			break;
		case Object:
		default:
	    	if ("".equals(prefix)) {
	    		tags[0] = ("<Object xmlns=\"" + XMLSignature.XMLNS + "\" Id=\"" + SIGNATURE_REF_ID + "\">").getBytes();
	    		tags[1] = "</Object>".getBytes();
	    	} else {
	    		tags[0] = ("<" + prefix + ":Object xmlns" + ":" + prefix + "=\"" + XMLSignature.XMLNS + "\" Id=\"" + SIGNATURE_REF_ID + "\">").getBytes(); 
	    		tags[1] = ("</" + prefix + ":Object>").getBytes();
	    	}
			break;
		}
		return tags;
	}
	
	protected String calcCanonicalizedXmlMsgDigestByParsingDocChunk(String infile, MessageDigest messageDigest, SigRefIdPos sigRefIdPos, SigXmlTransform xmlTransform) throws Exception {
		logger.debug("--> calcCanonicalizedXmlMsgDigestByParsingDocNoChunk(). infile=" + infile + ",sigRefIdPos=" + sigRefIdPos + ", xmlTransform=" + xmlTransform);
    	StringBuilder sbns = new StringBuilder(), sbChunk = new StringBuilder(), parseBuf = new StringBuilder();
		String startPrefixTags, endSuffixTags, prefix, localname, nsuri, qnameS, retEndXml = null, tmpS;
		XMLStreamReader reader = null;
		//hashNS is created at start elem and destroyed at end elem. It contains all inherited NS and new ones, if defined 
		//hashChunkNS is created at start elem of a chunk and destroyed once chunk is processed. It contains only new NS defined in the chunk
		//for chunk processing, we need to add prefix start tags with those NS exists in hashNS but not in hashChunkNS  
		HashMap<String, String> hashNS = new HashMap<String, String>(), hashChunkNS = new HashMap<String, String>();
		//stackTag pushes tag in start elem and pop/destroy in end elem. stackChunkStartTag contains start tag of chunk, popped in end tag
		//stackChunkEndTag contains end tags in chunk for missing start tag in chunk. For chunk processing, for each stackChunkEndTag elements, a start tag prefix is created 
		Stack<String> stackTag = new Stack<String>(), stackChunkStartTag = new Stack<String>(), stackChunkEndTag = new Stack<String>();
		//stackNS stacks hashNS which is created start of elem and popped/destroyed at end elem 
		Stack<HashMap<String, String>> stackNS = new Stack<HashMap<String,String>>();
		int minChunkSize = myThreadSafeData.getXmlChunkStreamingSize(), nscount, count, pos;
		Iterator<String> iter;
		boolean isEndDoc = false;
		try {
			byte[][] sigRefIdPosTags = getSigRefIdPosTags(sigRefIdPos);
			byte[] digestPrefix = sigRefIdPosTags[0], digestSuffix = sigRefIdPosTags[1];
    		messageDigest.update(digestPrefix);
    		if (digestBuf != null) {
        		digestBuf.setLength(0);
        		digestBuf.append(new String(digestPrefix));
        	}
			Canonicalizer canonicalizer = Canonicalizer.getInstance(getCanonicalizationMethod(xmlTransform));
	    	DocumentBuilderFactory dbfNSTrue = DocumentBuilderFactory.newInstance();
	        dbfNSTrue.setNamespaceAware(true);
	        DocumentBuilder docBuilderNSTrue = dbfNSTrue.newDocumentBuilder();
			docBuilderNSTrue.setErrorHandler(new IgnoreAllErrorHandler());
			reader = XMLInputFactory.newFactory().createXMLStreamReader(new FileReader(new File(infile)));
			while(!isEndDoc) {
				sbChunk.setLength(0);
				switch(reader.getEventType()) {
				case XMLStreamConstants.START_ELEMENT:
					prefix = reader.getPrefix();
					localname = reader.getLocalName();
					qnameS = (prefix == "" ? "" : prefix + ":") + localname;
					stackTag.push(qnameS);
					stackChunkStartTag.push(qnameS);
					sbChunk.append('<');
				    sbChunk.append(qnameS);
					nscount = reader.getNamespaceCount();
					if (nscount > 0) {
						if (!stackNS.empty()) {
							@SuppressWarnings("unchecked")
							HashMap<String, String> tmpHashNS = (HashMap<String, String>)stackNS.peek().clone(); //clone parent hashNS to inherit parent hashNS
							hashNS = tmpHashNS;
						}
						else
							hashNS = new HashMap<String, String>();
						stackNS.push(hashNS);
						for (int i = 0; i < nscount; i++) {
							prefix = reader.getNamespacePrefix(i);
							nsuri = reader.getNamespaceURI(i);
							if (nsuri == null)
								nsuri = "";
							nsuri = "\"" + nsuri + "\"";
							sbChunk.append(" ");
							sbChunk.append("xmlns");
							if (prefix != null) {
								sbChunk.append(":");
								sbChunk.append(prefix);
								hashNS.put("xmlns:" + prefix, nsuri);
								hashChunkNS.put("xmlns:" + prefix, nsuri);
							} else {
								hashNS.put("xmlns", nsuri);
								hashChunkNS.put("xmlns", nsuri);
							}
							sbChunk.append("=");
							sbChunk.append(nsuri);
						}
					}
					count = reader.getAttributeCount();
					for (int i = 0; i < count; i++) {
						tmpS = reader.getAttributeValue(i);
						localname = reader.getAttributeLocalName(i);
						prefix = reader.getAttributePrefix(i);
						sbChunk.append(" " + ("".equals(prefix) ? localname : (prefix + ":" + localname)) + "=\"" + tmpS + "\"");
					}
					sbChunk.append(">");
					parseBuf.append(sbChunk.toString());
			    	break;
				case XMLStreamConstants.CHARACTERS:
					tmpS = reader.getText();
					tmpS = tmpS.replace("&", "&#x26;").replace("\"", "&#x22;").replace("'", "&#x27;").replace("<", "&#x3C;").replace(">", "&#x3E;");
					//not sure if this is needed
					tmpS = tmpS.replace("\r", "&#xD;").replace("\n", "&#xA;");
					parseBuf.append(tmpS);
					break;
				case XMLStreamConstants.END_DOCUMENT:
					isEndDoc = true;
					minChunkSize = 0; // take whatever is left
					//do not break
				case XMLStreamConstants.END_ELEMENT:
					if (!isEndDoc) {
						//end element
					    stackTag.pop();
						prefix = reader.getPrefix();
						localname = reader.getLocalName();
						qnameS = (prefix == "" ? "" : prefix + ":") + localname;
						retEndXml = "</" + qnameS + ">";
						sbChunk.append(retEndXml);
					    if (stackChunkStartTag.empty())
					    	stackChunkEndTag.push(qnameS); // no corresponding tag in chunk start tag 
					    else
					    	stackChunkStartTag.pop();
					}
				    parseBuf.append(sbChunk.toString());
				    if (parseBuf.length() > minChunkSize) {
				    	startPrefixTags = ""; endSuffixTags = "";
				    	sbns.setLength(0);
				    	//add NS from hashNS which is not in hashChunkNS
				    	iter = hashNS.keySet().iterator();
				    	while(iter.hasNext()) {
				    		tmpS = iter.next();
				    		if (!hashChunkNS.containsKey(tmpS))
				    			sbns.append(" " + tmpS + "=" + hashNS.get(tmpS));
				    	}
				    	boolean isStartPrefixTag = true;
				    	//canonicalization may modify startPrefixTags so note startPrefixTagCount to drop startPrefixTags after canonicalization
				    	int startPrefixTagCount = 0;
				    	count = stackTag.size();
				    	//traverse stackTag from oldest inserted tag to newest ones 
				    	for (int i = 0; i < count; i++) {
				    		localname = stackTag.get(i);
				    		//if stackChunkStartTag oldest entry matches stackTag current entry then no more need for stackTag entries for startPrefixTags as start tag exists in chunk 
				    		if (isStartPrefixTag && !stackChunkStartTag.empty() && localname.equals(stackChunkStartTag.get(0)))
				    			isStartPrefixTag = false;
				    		if (isStartPrefixTag) {
					    		if (i == 0)
					    			startPrefixTags += "<" + localname + sbns.toString() + ">";
					    		else
					    			startPrefixTags += "<" + localname + ">";
					    		startPrefixTagCount++;
				    		}
			    			endSuffixTags = "</" + localname + ">" + endSuffixTags;
				    	}
				    	//add missing start tag in chunk whose end tag exists in chunk with no corresponding start tag
				    	boolean isFirstIteration = true;
				    	while(!stackChunkEndTag.empty()) {
				    		localname = stackChunkEndTag.pop();
				    		//"".equals(startPrefixTags) checks is to determine whether sbns has been considered or not
				    		if (isFirstIteration && "".equals(startPrefixTags))
				    			startPrefixTags += "<" + localname + sbns.toString() + ">";
				    		else
				    			startPrefixTags += "<" + localname + ">";
			    			isFirstIteration = false;
			    			startPrefixTagCount++;
				    	}
				    	String modifiedval = startPrefixTags + parseBuf.toString() + endSuffixTags;
				    	Document doc = docBuilderNSTrue.parse(new InputSource(new StringReader(modifiedval)));
						String digestval = new String(canonicalizer.canonicalizeSubtree(doc));
						if (endSuffixTags.length() > 0)
							digestval = digestval.substring(0, digestval.length() - endSuffixTags.length()); //simply drop endSuffixTags - they don't gets altered by canonicalization
						//drop startPrefixTags after canonicalization 
						pos = 0;
						for (int i = 0; i < startPrefixTagCount; i++)
							pos = digestval.indexOf(">", pos + 1);
						if (pos > 0)
							digestval = digestval.substring(pos + 1);
						logger.trace("digestval=" + digestval);
						messageDigest.update(digestval.getBytes());
						if (digestBuf != null) 
							digestBuf.append(digestval);
						parseBuf.setLength(0);
				    	hashChunkNS.clear();
				    	stackChunkStartTag.clear();
				    	stackChunkEndTag.clear();
				    }
				    if (!isEndDoc) {
						nscount = reader.getNamespaceCount();
						if (nscount > 0)
							stackNS.pop();
				    }
			    	break;
				}
				if (reader.hasNext())
					reader.next();
			}
			reader.close();
			reader = null;
			messageDigest.update(digestSuffix);
			if (digestBuf != null)
	    		digestBuf.append(new String(digestSuffix));
		} finally {
			if (reader != null) try{reader.close();}catch(Exception e){}
		}
		logger.debug("<-- calcCanonicalizedXmlMsgDigestByParsingDocChunk()");
		return retEndXml;
	}

	protected String calcCanonicalizedXmlMsgDigestByParsingDocNoChunk(String infile, MessageDigest messageDigest, SigRefIdPos sigRefIdPos, SigXmlTransform xmlTransform) throws Exception {
		logger.debug("--> calcCanonicalizedXmlMsgDigestByParsingDocNoChunk(). infile=" + infile + ",sigRefIdPos=" + sigRefIdPos + ", xmlTransform=" + xmlTransform);
		String retEndXml = null;
		StringBuilder parseBuf = new StringBuilder();
		String prefix, localname, nsuri, qnameS, tmpS;
		XMLStreamReader reader = null;
		DocumentBuilder docBuilderNSTrue = null;
		int count;
		try {
	    	DocumentBuilderFactory dbfNSTrue = DocumentBuilderFactory.newInstance();
	        dbfNSTrue.setNamespaceAware(true);
            Canonicalizer canonicalizer = Canonicalizer.getInstance(getCanonicalizationMethod(xmlTransform));
    		docBuilderNSTrue = dbfNSTrue.newDocumentBuilder();
			docBuilderNSTrue.setErrorHandler(new IgnoreAllErrorHandler());
			XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
			BufferedReader br = new BufferedReader(new FileReader(new File(infile)));
			reader = xmlInputFactory.createXMLStreamReader(br);
			int nsCount = -1;
			String wrapperPrefix, wrapperNSUri;
			byte[][] sigRefIdPosTags = getSigRefIdPosTags(sigRefIdPos);
			byte[] digestPrefix = sigRefIdPosTags[0], digestSuffix = sigRefIdPosTags[1];
    		messageDigest.update(digestPrefix);
    		if (digestBuf != null) {
        		digestBuf.setLength(0);
        		digestBuf.append(new String(digestPrefix));
        	}
			while(reader != null && reader.hasNext()) {
				parseBuf.setLength(0);
				wrapperNSUri = wrapperPrefix = null;
				switch(reader.getEventType()) {
				case XMLStreamConstants.START_ELEMENT:
					prefix = reader.getPrefix();
					localname = reader.getLocalName();
					qnameS = (prefix == "" ? "" : prefix + ":") + localname;
					parseBuf.append('<');
					if (prefix != null && !"".equals(prefix)) {
						wrapperPrefix = prefix;
					    parseBuf.append(prefix + ":");
					}
				    parseBuf.append(localname);
					nsCount = reader.getNamespaceCount();
					if (nsCount == 0)
						wrapperNSUri = reader.getNamespaceURI();
					for (int i = 0; i < nsCount; i++) {
						prefix = reader.getNamespacePrefix(i);
						nsuri = reader.getNamespaceURI(i);
						if (nsuri == null)
							nsuri = "";
						parseBuf.append(" ");
						parseBuf.append("xmlns");
						if (prefix != null && !"".equals(prefix)) {
							parseBuf.append(":");
							parseBuf.append(prefix);
						}
						parseBuf.append("=\"");
						parseBuf.append(nsuri);
						parseBuf.append("\"");
					}
					count = reader.getAttributeCount();
					for (int i = 0; i < count; i++) {
						tmpS = reader.getAttributeValue(i);
						localname = reader.getAttributeLocalName(i);
						prefix = reader.getAttributePrefix(i);
						parseBuf.append(" " + ("".equals(prefix) ? localname : (prefix + ":" + localname)) + "=\"" + tmpS + "\"");
					}
					parseBuf.append(">");
					processXmlFrag(STARTTAG, qnameS, parseBuf.toString(), messageDigest, canonicalizer, docBuilderNSTrue, wrapperPrefix, wrapperNSUri);
			    	break;
				case XMLStreamConstants.CHARACTERS:
					tmpS = reader.getText();
					tmpS = tmpS.replace("&", "&#x26;").replace("\"", "&#x22;").replace("'", "&#x27;").replace("<", "&#x3C;").replace(">", "&#x3E;");
					//not sure if this is needed
					tmpS = tmpS.replace("\r", "&#xD;").replace("\n", "&#xA;");
					processXmlFrag(CHAR, "", reader.getText(), messageDigest, canonicalizer, docBuilderNSTrue, null, null);
					break;
				case XMLStreamConstants.END_ELEMENT:
					prefix = reader.getPrefix();
					localname = reader.getLocalName();
					qnameS = (prefix == "" ? "" : prefix + ":") + localname;
				    parseBuf.append("</");
					if (prefix != null && !"".equals(prefix)) {
						wrapperPrefix = prefix;
					    parseBuf.append(prefix + ":");
					}
					wrapperNSUri = reader.getNamespaceURI();
				    parseBuf.append(localname);
				    parseBuf.append('>');
					processXmlFrag(ENDTAG, qnameS, parseBuf.toString(), messageDigest, canonicalizer, docBuilderNSTrue, wrapperPrefix, wrapperNSUri);
			    	retEndXml = parseBuf.toString();
			    	break;
				}
				reader.next();
			}
			reader.close();
			br.close();
			reader = null;
			messageDigest.update(digestSuffix);
			if (digestBuf != null)
	    		digestBuf.append(new String(digestSuffix));
		} finally {
			if (reader != null) try{reader.close();}catch(Exception e){}
		}
		logger.debug("<-- calcCanonicalizedXmlMsgDigestByParsingDocNoChunk()");
		return retEndXml;
	}
	
    protected void calcXmlMsgDigestNoTransformation(String infile, MessageDigest messageDigest, SigRefIdPos sigRefIdPos) throws Exception {
		logger.debug("--> calcXmlMsgDigestNoTransformation(). infile=" + infile + ",sigRefIdPos=" + sigRefIdPos);
		int len;
		String tmp;
		byte[][] sigRefIdPosTags = getSigRefIdPosTags(sigRefIdPos);
		byte[] digestPrefix = sigRefIdPosTags[0], digestSuffix = sigRefIdPosTags[1];
		messageDigest.update(digestPrefix);
		if (digestBuf != null) {
    		digestBuf.setLength(0);
    		digestBuf.append(new String(digestPrefix));
    	}
    	BufferedInputStream bis = new BufferedInputStream(new FileInputStream(new File(infile)));
		boolean flag = true;
		byte[] tmpBuf = new byte[myThreadSafeData.getBufSize()];
		while((len = bis.read(tmpBuf)) != -1) {
			tmp = new String(tmpBuf, 0, len);
			if (flag) {
				flag = false;
				tmp = UtilShared.stripXmlHeader(tmp);
			}
			// remove CR for digest calc
			tmp = tmp.replace("\r", "");
    		if (digestBuf != null)
				digestBuf.append(tmp);
			messageDigest.update(tmp.getBytes());
		}
		bis.close();
		messageDigest.update(digestSuffix);
		if (digestBuf != null)
    		digestBuf.append(new String(digestSuffix));
		logger.debug("<-- calcXmlMsgDigestNoTransformation()");
    }
    
    protected void calcTextMsgDigestNoTransformation(String infile, MessageDigest messageDigest, SigRefIdPos sigRefIdPos) throws Exception {
		logger.debug("--> calcTextMsgDigestNoTransformation(). infile=" + infile + ",sigRefIdPos=" + sigRefIdPos);
		int len;
		String tmp;
		byte[][] sigRefIdPosTags = getSigRefIdPosTags(sigRefIdPos);
		byte[] digestPrefix = sigRefIdPosTags[0], digestSuffix = sigRefIdPosTags[1];
		messageDigest.update(digestPrefix);
		if (digestBuf != null) {
    		digestBuf.setLength(0);
    		digestBuf.append(new String(digestPrefix));
    	}
    	BufferedInputStream bis = new BufferedInputStream(new FileInputStream(new File(infile)));
		byte[] tmpBuf = new byte[myThreadSafeData.getBufSize()];
		while((len = bis.read(tmpBuf)) != -1) {
			tmp = new String(tmpBuf, 0, len);
			tmp = tmp.replace("\r", "&#xD;");
			if (digestBuf != null)
				digestBuf.append(tmp);
			messageDigest.update(tmp.getBytes());
		}
		bis.close();
		messageDigest.update(digestSuffix);
		if (digestBuf != null)
    		digestBuf.append(new String(digestSuffix));
		logger.debug("<-- calcTextMsgDigestNoTransformation()");
    }
    
    protected Document createBlankSignedDOMDocForStreamingSignature(PrivateKey sigkey, X509Certificate sugPubCert, 
    		SigDocType sigDocType, SigRefIdPos sigRefIdPos, SigXmlTransform xmlTransform) throws Exception {
    	return createSignedDOMDoc(null, sigkey, sugPubCert, sigDocType, sigRefIdPos, xmlTransform);
    }

	protected Document createSignedDOMDoc(String infile, PrivateKey sigkey, X509Certificate sugPubCert, 
			SigDocType sigDocType, SigRefIdPos sigRefIdPos, SigXmlTransform xmlTransform) throws Exception {
		logger.debug("--> createSignedDOMDoc(). infile=" + infile + ", sigDocType=" + sigDocType + ", sigRefIdPos=" + sigRefIdPos + ", xmlTransform=" + xmlTransform);
    	BufferedInputStream bis = null;
        Document doc = null;
        int len;
    	XMLObject xmlobj = null;
    	List<Transform> transforms = null;
        SignatureProperty sigProp;
        SignatureProperties sigProps;
        Node node = null;
		String tmp = null;
    	try {
    		DocumentBuilderFactory dbfNSTrue = DocumentBuilderFactory.newInstance();
            dbfNSTrue.setNamespaceAware(true);
            DocumentBuilder docBuilderNSTrue = dbfNSTrue.newDocumentBuilder();
            docBuilderNSTrue.setErrorHandler(new IgnoreAllErrorHandler());
            if (infile == null) {
            	// streaming signature
    			tmp = Base64.encode(UtilShared.genRandomId().getBytes()); // cover binary transform
    			doc = docBuilderNSTrue.newDocument();
    			node = doc.createTextNode(tmp);
            } else {
            	// DOM signature
                switch(sigDocType) {
                case XML:
                case WRAPPEDXML:
           	        doc = docBuilderNSTrue.parse(new File(infile));
           	        node = doc.getDocumentElement();
                	break;
                case BINARY:	// not used in FATCA
            		ByteArrayOutputStream baos = new ByteArrayOutputStream();
            		writeBase64BinaryAndOptionallyCalcMsgDigest(infile, "\n", baos, false, null);
                	baos.close();
            		doc = docBuilderNSTrue.newDocument();
                	node = doc.createTextNode(baos.toString());
                	break;
                case TEXT:		// not used in FATCA
            		StringBuffer sb = new StringBuffer();
                	bis = new BufferedInputStream(new FileInputStream(new File(infile)));
                	byte[] buf = new byte[myThreadSafeData.getBufSize()];
                	while((len = bis.read(buf)) != -1)
                		sb.append(new String(buf, 0, len));
                	bis.close(); bis = null;
            		doc = docBuilderNSTrue.newDocument();
            		node = doc.createTextNode(sb.toString());
                	break;
                }
            }
            XMLSignatureFactory xmlSigFactory;
            if (defaultSignatureFactoryProvider != null) 
    			xmlSigFactory = XMLSignatureFactory.getInstance("DOM", defaultSignatureFactoryProvider);
    		 else
    			xmlSigFactory = XMLSignatureFactory.getInstance();
    		if (sigDocType == SigDocType.XML) {
            	if (xmlTransform != SigXmlTransform.None)
               		transforms = Collections.singletonList(xmlSigFactory.newTransform(getCanonicalizationMethod(xmlTransform), (TransformParameterSpec) null));
            } else if (sigDocType == SigDocType.BINARY) {
                // not used in FATCA
            	transforms = Collections.singletonList(xmlSigFactory.newTransform(CanonicalizationMethod.BASE64, (TransformParameterSpec) null));
            }
        	XMLStructure content = new DOMStructure(node);
    		switch(sigRefIdPos) {
    		case Object:
                xmlobj = xmlSigFactory.newXMLObject(Collections.singletonList(content), SIGNATURE_REF_ID, null, null);
            	break;
    		case SignatureProperty:
    			sigProp = xmlSigFactory.newSignatureProperty(Collections.singletonList(content), "#" + SIGNATURE_ID, SIGNATURE_REF_ID);
    			sigProps = xmlSigFactory.newSignatureProperties(Collections.singletonList(sigProp), null);
    			xmlobj = xmlSigFactory.newXMLObject(Collections.singletonList(sigProps), null, null, null);
    			break;
    		case SignatureProperties:
    			sigProp = xmlSigFactory.newSignatureProperty(Collections.singletonList(content), "#" + SIGNATURE_ID, null);
    			sigProps = xmlSigFactory.newSignatureProperties(Collections.singletonList(sigProp), SIGNATURE_REF_ID);
    			xmlobj = xmlSigFactory.newXMLObject(Collections.singletonList(sigProps), null, null, null);
    			break;
    		}
        	List<XMLObject> xmlObjs = Collections.singletonList(xmlobj);
            Reference sigref = xmlSigFactory.newReference("#" + SIGNATURE_REF_ID, xmlSigFactory.newDigestMethod(SIGNATURE_DIGEST_METHOD, null), transforms, null, null);
            SignedInfo signedInfo = xmlSigFactory.newSignedInfo(
            		xmlSigFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
            		xmlSigFactory.newSignatureMethod(SIGNATURE_METHOD, null),
            		Collections.singletonList(sigref));
            KeyInfo keyInfo = null;
            if (sugPubCert != null) {
	            List<X509Certificate> list = new ArrayList<X509Certificate>();
	            list.add(sugPubCert);
	            KeyInfoFactory keyInfoFactory = xmlSigFactory.getKeyInfoFactory();
	            X509Data kv = keyInfoFactory.newX509Data(list);
	            keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(kv));
            }
            XMLSignature signature = xmlSigFactory.newXMLSignature(signedInfo, keyInfo, xmlObjs, SIGNATURE_ID, null);
	        doc = docBuilderNSTrue.newDocument();
            DOMSignContext dsc = new DOMSignContext(sigkey, doc);
            String sigprefix = myThreadSafeData.getSignaturePrefix();
            if (sigprefix != null && !"".equals(sigprefix))
            	dsc.setDefaultNamespacePrefix(sigprefix);
           	signature.sign(dsc);
    	} finally {
    		if (bis != null) try{bis.close();}catch(Exception e){}
    	}
		logger.debug("<-- createSignedDOMDoc()");
    	return doc;
    }
	
	protected int writeEncodedBinary(int lastlinelen, byte[] buf, String newline, OutputStream os) throws Exception {
		String encoded = Base64.encode(buf).replaceAll("\r", "").replaceAll("\n", "");
		int strlen = encoded.length();
		if (lastlinelen + strlen < 76) {
			os.write(encoded.getBytes());
			lastlinelen += strlen;
		} else {
			String tmpS = encoded.substring(0, 76 - lastlinelen);
			os.write(tmpS.getBytes());
			os.write(newline.getBytes());
			encoded = encoded.substring(tmpS.length());
			lastlinelen = 0;
			while (encoded.length() >= 76) {
				tmpS = encoded.substring(0, 76 - lastlinelen);
				os.write(tmpS.getBytes());
				os.write(newline.getBytes());
				encoded = encoded.substring(tmpS.length());
			}
			if (encoded.length() > 0) {
				os.write(encoded.getBytes());
				lastlinelen = encoded.length();
			}
		}
		return lastlinelen;
	}
	
	protected boolean writeXmlFileObjectContent(String infile, OutputStream os, String endXml) throws Exception {
		logger.debug("--> writeXmlFileObjectContent(). infile=" + infile);
    	boolean ret = false;
    	String tmp;
    	BufferedInputStream bis = new BufferedInputStream(new FileInputStream(new File(infile)));
        int len;
        boolean flag = true;
        byte[] tmpBuf = new byte[myThreadSafeData.getBufSize()];
        int pos;
        while((len = bis.read(tmpBuf)) != -1) {
			tmp = new String(tmpBuf, 0, len);
			if (flag) {
				flag = false;
				tmp = UtilShared.stripXmlHeader(tmp);
			}
//			// do we really need this??
//			tmp = tmp.replace("\r", "");
//			tmp = tmp.replace("\n", "\r\n");
			if (endXml != null && (pos = tmp.indexOf(endXml)) != -1) {
				tmp = tmp.substring(0, pos + endXml.length());
				os.write(tmp.getBytes());
				break;
			} else 
				os.write(tmp.getBytes());
        }
        bis.close();
		logger.debug("<-- writeXmlFileObjectContent()");
    	return ret;
	}
    
	protected boolean writeTextFileObjectContent(String infile, OutputStream os) throws Exception {
		logger.debug("--> writeTextFileObjectContent(). infile=" + infile);
    	boolean ret = false;
    	String tmp;
    	BufferedInputStream bis = new BufferedInputStream(new FileInputStream(new File(infile)));
        int len;
        byte[] tmpBuf = new byte[myThreadSafeData.getBufSize()];
        while((len = bis.read(tmpBuf)) != -1) {
			tmp = new String(tmpBuf, 0, len);
			tmp = tmp.replace("\r", "&#13;");
			//tmp = tmp.replace("\r", "&#xD;");
			// do we really need this??
			tmp = tmp.replace("\n", "\r\n");
			os.write(tmp.getBytes());
        }
        bis.close();
		logger.debug("<-- writeTextFileObjectContent()");
    	return ret;
	}
	
    protected boolean signFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sigPubCert, 
    		SigDocType sigDocType, SigRefIdPos sigRefIdPos, SigXmlTransform xmlTransform) throws Exception {
		logger.debug("--> signFileStreaming(). infile=" + infile + ", outfile=" + outfile + ", sigDocType=" + sigDocType + ", sigRefIdPos=" + sigRefIdPos + ", xmlTransform=" + xmlTransform);
    	boolean ret = false;
        ByteArrayOutputStream baos = null;
        BufferedOutputStream bos = null;
        BufferedInputStream bis = null;
        String base64BinaryFile = null;
    	try {
    		Node node;
    		Transformer trans;
    		NodeList nodeList;
    		MessageDigest messageDigest;
    		Signature signature;
    		if (defaultMessageDigestProvider != null)
    			messageDigest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGO, defaultMessageDigestProvider);
    		else
    			messageDigest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGO);
    		String endXml = null;
    		switch(sigDocType) {
    		case XML:
    	    	logger.debug("parsing xml...." + new Date());
    	    	if (myThreadSafeData.isXmlChunkStreaming())
    	    		endXml = calcCanonicalizedXmlMsgDigestByParsingDocChunk(infile, messageDigest, sigRefIdPos, xmlTransform);
    	    	else
    	    		endXml = calcCanonicalizedXmlMsgDigestByParsingDocNoChunk(infile, messageDigest, sigRefIdPos, xmlTransform);
	    		logger.debug("parsing xml....done. " + new Date());
				break;
    		case WRAPPEDXML:
				calcXmlMsgDigestNoTransformation(infile, messageDigest, sigRefIdPos);
				break;
    		case TEXT:	// not used in FATCA
    			calcTextMsgDigestNoTransformation(infile, messageDigest, sigRefIdPos);
    			break;
    		case BINARY:	// not used in FATCA
    			base64BinaryFile = UtilShared.getTmpFileName(infile, "base64");
    			bos = new BufferedOutputStream(new FileOutputStream(new File(base64BinaryFile)));
                writeBase64BinaryAndOptionallyCalcMsgDigest(infile, "\r\n", bos, true, messageDigest);
                bos.close(); bos = null;
    			break;
    		}
            Document doc = createBlankSignedDOMDocForStreamingSignature(sigkey, sigPubCert, sigDocType, sigRefIdPos, xmlTransform);
    		nodeList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestValue");
            if (nodeList.getLength() > 0) {
            	node = nodeList.item(0);
            	node = node.getFirstChild();
            	String digestValue = Base64.encode(messageDigest.digest());
            	logger.debug("DigestVal=" + digestValue);
            	node.setNodeValue(digestValue);
            } else
            	throw new Exception("Invalid document structure. Missing <DigestValue> content");
            String signatureValue = null;
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            nodeList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignedInfo");
            if (nodeList.getLength() > 0) {
            	node = nodeList.item(0); 
                baos = new ByteArrayOutputStream();
                trans = transformerFactory.newTransformer();
                trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
                trans.transform(new DOMSource(node), new StreamResult(baos));
                baos.close();
                Canonicalizer canonicalizer = Canonicalizer.getInstance(CanonicalizationMethod.INCLUSIVE);
                if (defaultSignatureProvider != null)
                	signature = Signature.getInstance(SIGNATUER_ALGO, defaultSignatureProvider);
                else
                	signature = Signature.getInstance(SIGNATUER_ALGO);
                signature.initSign(sigkey);
				signature.update(canonicalizer.canonicalize(baos.toByteArray()));
				byte[] signatureBuf = signature.sign();
    			signatureValue = Base64.encode(signatureBuf);
    			baos = null;
            } else
            	throw new Exception("Invalid document structure. Missing <SignedInfo> content");
            nodeList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
            if (nodeList.getLength() > 0) {
            	nodeList.item(0).getFirstChild().setNodeValue(signatureValue);
            } else
            	throw new Exception("Invalid document structure. Missing <SignatureValue> content");
            String textContent = null;
    		nodeList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Object");
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
            bos = new BufferedOutputStream(new FileOutputStream(new File(outfile)));
            bos.write(prefix.getBytes());
    		switch(sigDocType) {
    		case XML:
    		case WRAPPEDXML:
                writeXmlFileObjectContent(infile, bos, endXml);
    			break;
    		case TEXT:	// not used in FATCA
    			writeTextFileObjectContent(infile, bos);
    			break;
    		case BINARY:	// not used in FATCA
    			bis = new BufferedInputStream(new FileInputStream(new File(base64BinaryFile)));
    			int len;
    			byte[] buf = new byte[myThreadSafeData.getBufSize()];
    			while ((len = bis.read(buf)) != -1)
    				bos.write(buf, 0, len);
    			bis.close(); bis = null;
    			break;
    		}
            bos.write(suffix.getBytes());
            bos.close(); bos = null;
        	ret = true;
    	} finally {
    		if (bos != null) try{bos.close();}catch(Exception e){}
    		if (baos != null) try{baos.close();}catch(Exception e){}
    		if (bis != null) try{bis.close();}catch(Exception e){}
    		if (base64BinaryFile != null) try{File f = new File(base64BinaryFile);if (f.exists()&&!f.delete())f.deleteOnExit();}catch(Exception e){}
    	}
    	if (isValidateAllSignature) {
    		boolean flag = UtilShared.verifySignatureDOM(outfile, sigPubCert.getPublicKey());
    		synchronized (isValidationSuccess) {
    			isValidationSuccess &= flag;
			}
    	}
    	logger.debug("<-- signFileStreaming()");
    	return ret;
    }

    protected boolean signFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sigPubCert, 
    		SigDocType sigDocType, SigRefIdPos sigRefIdPos, SigXmlTransform xmlTransform) throws Exception {
		logger.debug("--> signFile(). infile=" + infile + ", outfile=" + outfile + ", sigDocType=" + sigDocType + ", sigRefIdPos=" + sigRefIdPos + ", xmlTransform=" + xmlTransform);
		BufferedOutputStream bos = null;
		boolean ret = false;
    	try {
	    	Document doc = createSignedDOMDoc(infile, sigkey, sigPubCert, sigDocType, sigRefIdPos, xmlTransform);
    		NodeList nodeList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestValue");
	        if (nodeList.getLength() > 0) {
	        	logger.debug("DigestValue=" + nodeList.item(0).getFirstChild().getNodeValue());
	        }
	    	bos = new BufferedOutputStream(new FileOutputStream(new File(outfile)));
	    	Transformer transformer = TransformerFactory.newInstance().newTransformer();
	        transformer.transform(new DOMSource(doc), new StreamResult(bos));
	        ret = true;
		} finally {
			if (bos != null) try{bos.close();}catch(Exception e) {}
		}
    	if (isValidateAllSignature) {
    		boolean flag = UtilShared.verifySignatureDOM(outfile, sigPubCert.getPublicKey());
    		synchronized (isValidationSuccess) {
    			isValidationSuccess &= flag;
			}
    	}
		logger.debug("<-- signFile()");
    	return ret;
    }
    
    protected boolean signFileNoWrap(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert, 
    		boolean isDom, SigDocType sigDocType, SigRefIdPos sigRefIdPos, SigXmlTransform xmlTransform) throws Exception {
		logger.debug("--> signFileNoWrap(). infile=" + infile + ", outfile=" + outfile + ", isDom=" + isDom + ", sigDocType=" + sigDocType + ", sigRefIdPos=" + sigRefIdPos  + ", xmlTransform=" + xmlTransform);
    	boolean flag = false;
    	if (isDom)
    		flag = signFile(infile, outfile, sigkey, sugPubCert, sigDocType, sigRefIdPos, xmlTransform);
    	else
    		flag = signFileStreaming(infile, outfile, sigkey, sugPubCert, sigDocType, sigRefIdPos, xmlTransform);
    	logger.debug("<-- signFileNoWrap()");
		return flag;
    }

    public void setSignaturePrefix(String prefix) {
    	myThreadSafeData.setSignaturePrefix(prefix);
    }
    
    public void setBufSize(int val) {
		myThreadSafeData.setBufSize(val);
	}
	
	public void setXmlChunkStreaming(boolean val) {
		myThreadSafeData.setXmlChunkStreaming(val);
	}

	public void setXmlChunkStreamingSize(int val) {
		myThreadSafeData.setXmlChunkStreamingSize(val);
	}

    // not used in FATCA
    public boolean signTextFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert, SigRefIdPos sigRefIdPos) throws Exception {
    	return signFileNoWrap(infile, outfile, sigkey, sugPubCert, true, SigDocType.TEXT, sigRefIdPos, null);
    }

    // not used in FATCA
    public boolean signBinaryFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert, SigRefIdPos sigRefIdPos) throws Exception {
    	return signFileNoWrap(infile, outfile, sigkey, sugPubCert, true, SigDocType.BINARY, sigRefIdPos, null);
    }
    
    public boolean signXmlFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert, SigRefIdPos sigRefIdPos, SigXmlTransform xmlTransform) throws Exception {
    	return signFileNoWrap(infile, outfile, sigkey, sugPubCert, true, SigDocType.XML, sigRefIdPos, xmlTransform);
    }
    
    public boolean signXmlFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	return signXmlFile(infile, outfile, sigkey, sugPubCert, SigRefIdPos.Object, SigXmlTransform.Inclusive);
    }
    
    // not used in FATCA
    public boolean signTextFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert, SigRefIdPos sigRefIdPos) throws Exception {
    	return signFileNoWrap(infile, outfile, sigkey, sugPubCert, false, SigDocType.TEXT, sigRefIdPos, null);
    }

    // not used in FATCA
    public boolean signBinaryFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert, SigRefIdPos sigRefIdPos) throws Exception {
    	return signFileNoWrap(infile, outfile, sigkey, sugPubCert, false, SigDocType.BINARY, sigRefIdPos, null);
    }
    
    public boolean signXmlFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert, SigRefIdPos sigRefIdPos, SigXmlTransform xmlTransform) throws Exception {
    	boolean isDom = false;
    	return signFileNoWrap(infile, outfile, sigkey, sugPubCert, isDom, SigDocType.XML, sigRefIdPos, xmlTransform);
    }

    public boolean signXmlFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	return signXmlFileStreaming(infile, outfile, sigkey, sugPubCert, SigRefIdPos.Object, SigXmlTransform.Inclusive);
    }

	// for backward compatibility
    public void signDOM(String xmlInputFile, String signedXmlOutputFile, PrivateKey signatureKey, X509Certificate signaturePublicKey) throws Exception {
		signXmlFile(xmlInputFile, signedXmlOutputFile, signatureKey, signaturePublicKey);
    }

	// for backward compatibility
    public boolean signStreaming(String xmlInputFile, String signedXmlOutputFile, PrivateKey signatureKey, X509Certificate signaturePublicCert) throws Exception {
    	return signXmlFileStreaming(xmlInputFile, signedXmlOutputFile, signatureKey, signaturePublicCert, SigRefIdPos.Object, SigXmlTransform.None);
    }
    
	// for backward compatibility
    public boolean signStreamingWithCanonicalization(String xmlInputFile, String signedXmlOutputFile, PrivateKey signatureKey, X509Certificate signaturePublicCert) throws Exception {
    	return signXmlFileStreaming(xmlInputFile, signedXmlOutputFile, signatureKey, signaturePublicCert, SigRefIdPos.Object, SigXmlTransform.Inclusive);
    }
}
