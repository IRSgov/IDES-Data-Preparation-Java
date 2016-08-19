package fatca.impl;

import fatca.intf.ISigner;
import fatca.util.UtilShared;

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
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
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
public class FATCAXmlSigner implements ISigner {
	protected Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

	//<Reference URI="#FATCA">, <Object Id="FATCA">
	protected final String xmlTagReferenceUriValue = "FATCA";
	//<Signature ...Id="SignatureId">
	protected final String xmlTagSignatureIdValue = "SignatureId";
	//<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
	protected final String xmlTagDigestMethodAlgoValue = DigestMethod.SHA256;
	//<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
	protected final String xmlTagSignatureMethodAlgoValue = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

	//Signature algorithm used to sign
	protected final String SIGNATUER_ALGO = "SHA256withRSA";
	//message digest calculation algorithm
	protected final String MESSAGE_DIGEST_ALGO = "SHA-256";

	protected Provider defaultSignatureFactoryProvider = null;
	protected Provider defaultSignatureProvider = null;
	protected Provider defaultMessageDigestProvider = null;
	
    //<Object Id="FATCA">[payload]</Object> or
    //<Object><SignatureProperties><SignatureProperty Id="FATCA">[payload]</SignatureProperty></SignatureProperties></Object> or 
    //<Object><SignatureProperties Id="FATCA"><SignatureProperty Target="#SignatureId">[payload]</SignatureProperty></SignatureProperties></Object>
	public enum SigRefIdPos {Object, SignatureProperty, SignatureProperties}
	
	//transformation/canonicalization to use for signing. transformation affects digest value and thus signature value 
	//Inclusive: <Transforms><Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></Transforms>
	//InclusiveWithComments: <Transforms><Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/></Transforms>
	//Exclusive: <Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>
	//ExclusiveWithComments: <Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/></Transforms>
	public enum SigXmlTransform {Inclusive, InclusiveWithComments, Exclusive, ExclusiveWithComments, None};
	
	public enum SigDocType {XML, 
		WRAPPEDXML, //binary (base64 encoded) and text files are wrapped in xml before signing 
		TEXT,	//not used in FATCA
 		BINARY	//not used in FATCA, uses Base64 transformation
	};

	//for xml parsing using streaming api for digest calculation
	protected final int STARTTAG = 0, ENDTAG = 1, CHAR = 2;
	
	protected int defaultBufSize = 8 * 1024;
	protected int defaultChunkStreamingSize = 8 * 1024;
	
	protected MyThreadSafeData myThreadSafeData = new MyThreadSafeData();
	
	private String uuid = UUID.randomUUID().toString().replace("-", "");
	
	// for debug only
	public StringBuilder digestBuf  = null;
	public boolean isValidateAllSignature = false;
	public Boolean isValidationSuccess = true;

	//thread safe data
	private class MyThreadSafeData {
		private String signaturePrefix = "";
		//base64 binary and text are wrapped in xml before signing
		private String wrapperPrefix = "";
		private String wrapperNS = "urn:xmpp:xml-element";
		private String wrapperXsi = "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"";
		private String wrapperXsiSchemaLoc = "xsi:schemaLocation=\"urn:xmpp:xml-element FATCA-IDES-FileWrapper-1.1.xsd\"";
		private Boolean useWrapperXsi = false;
		private Boolean useWrapperXsiSchemaLoc = false;
		
		private Boolean useXmlChunkStreaming = true;
		private Integer bufSize = defaultBufSize;
		private Integer xmlChunkStreamingSize = defaultChunkStreamingSize;
		private SigRefIdPos sigRefIdPos = SigRefIdPos.Object;
		private SigXmlTransform sigXmlTransform = SigXmlTransform.Inclusive;
		
		private final String genericLock = "genericLock", sigElemLock = "sigElemLock", wrapperLock = "wrapperLock";  

		public SigRefIdPos getSigRefIdPos() {
			synchronized (sigElemLock) {
				return sigRefIdPos;
			}
		}

		public void setSigRefIdPos(SigRefIdPos sigRefIdPos) {
			synchronized (sigElemLock) {
				this.sigRefIdPos = sigRefIdPos;
			}
		}

		public SigXmlTransform getSigXmlTransform() {
			synchronized (sigElemLock) {
				return sigXmlTransform;
			}
		}

		public void setSigXmlTransform(SigXmlTransform sigXmlTransform) {
			synchronized (sigElemLock) {
				this.sigXmlTransform = sigXmlTransform;
			}
		}

		public int getXmlChunkStreamingSize() {
	    	synchronized (genericLock) {
				return xmlChunkStreamingSize;
				
			}
		}
		
		public void setXmlChunkStreamingSize(int val) {
	    	synchronized (genericLock) {
	    		xmlChunkStreamingSize = val;
	    	}
		}
		
		public int getBufSize() {
			synchronized (genericLock) {
				return bufSize;
			}
		}
		
		public void setBufSize(int val) {
			synchronized (genericLock) {
				bufSize = val;
			}
		}
		
		protected boolean isXmlChunkStreaming() {
	    	synchronized (genericLock) {
	        	return useXmlChunkStreaming;
			}
	    }
	    
		protected void setXmlChunkStreaming(boolean val) {
	    	synchronized (genericLock) {
	        	useXmlChunkStreaming = val;
			}
	    }
		
		protected void setSignaturePrefix(String prefix) {
	    	synchronized (genericLock) {
	        	if (prefix == null)
	        		signaturePrefix = "";
	        	else
	        		signaturePrefix = prefix; 
			}
	    }
	    
		protected String getSignaturePrefix() {
	    	synchronized (genericLock) {
	        	return signaturePrefix;
			}
	    }
	    
		protected String getWrapperPrefix() {
	    	synchronized (wrapperLock) {
	        	return wrapperPrefix;
			}
	    }
	    
		protected String getWrapperNS() {
	    	synchronized (wrapperLock) {
	        	return wrapperNS;
			}
	    }
	    
		protected String getWrapperXsi() {
	    	synchronized (wrapperLock) {
	        	return wrapperXsi;
			}
	    }
	    
		protected String getWrapperXsiSchemaLoc() {
	    	synchronized (wrapperLock) {
	        	return wrapperXsiSchemaLoc;
			}
	    }
	    
		protected boolean isWrapperXsiSchemaLoc() {
	    	synchronized (wrapperLock) {
	        	return useWrapperXsiSchemaLoc;
			}
	    }
	    
		protected boolean isWrapperXsi() {
	    	synchronized (wrapperLock) {
	        	return useWrapperXsi;
			}
	    }
	    
		protected void setWrapperXsiSchemaLoc(String val) {
	    	synchronized (wrapperLock) {
	        	wrapperXsiSchemaLoc = "xsi:schemaLocation=\"" + val + "\"";
			}
	    }
	    
		protected void setWrapperXsiSchemaLoc(boolean val) {
	    	synchronized (wrapperLock) {
	        	useWrapperXsiSchemaLoc = val;
			}
	    }
	    
		protected void setWrapperXsi(boolean val) {
	    	synchronized (wrapperLock) {
	        	useWrapperXsi = val;
			}
	    }
	    
		protected void setWrapperPrefix(String prefix) {
	    	synchronized (wrapperLock) {
	        	if (prefix == null)
	        		wrapperPrefix = "";
	        	else
	        		wrapperPrefix = prefix; 
			}
	    }
	    
		protected void setWrapperNS(String ns) {
	    	synchronized (wrapperLock) {
	        	if (ns == null)
	        		wrapperNS = "";
	        	else
	        		wrapperNS = ns; 
			}
	    }
	}

	public FATCAXmlSigner() {
		if (!Init.isInitialized())
			Init.init();
    }
    
	//base64 binary and text are wrapped in xml before signing
	//returns start and end wrapper tags. Sample:<Wrapper xmlns="urn:xmpp:xml-element"> and </Wrapper>
	protected byte[][] getWrapperTags() throws Exception {
    	String ns = myThreadSafeData.getWrapperNS(), prefix = myThreadSafeData.getWrapperPrefix(), xsi = null, xsiSchemaLoc = null;
    	boolean isXsi = myThreadSafeData.isWrapperXsi(), isXsiSchemaLoc = myThreadSafeData.isWrapperXsiSchemaLoc();
    	if (isXsi) {
    		xsi = myThreadSafeData.getWrapperXsi();
    		if (isXsiSchemaLoc)
    			xsiSchemaLoc = myThreadSafeData.getWrapperXsiSchemaLoc();
    	}
    	if ("".equals(ns) && !"".equals(prefix))
    		throw new Exception("non-empty wrapperPrefix not allower for empty wrapperNS");
    	byte[][] tags = new byte[2][];
    	String startTag, endTag;
		Canonicalizer canonicalizer = Canonicalizer.getInstance(CanonicalizationMethod.INCLUSIVE);
    	if ("".equals(prefix)) {
    		//<Wrapper xmlns="urn:xmpp:xml-element" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:xmpp:xml-element FATCA-IDES-FileWrapper-1.1.xsd">
    		startTag = "<Wrapper xmlns=\"" + ns + "\"" + (xsi==null?"":" " + xsi + (xsiSchemaLoc==null?"":" " + xsiSchemaLoc)) + ">";
    		endTag = "</Wrapper>";
    	} else {
    		//<xyz:Wrapper xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xyz="urn:xmpp:xml-element" xsi:schemaLocation="urn:xmpp:xml-element FATCA-IDES-FileWrapper-1.1.xsd">
        	startTag = "<" + prefix + ":Wrapper xmlns" + ":" + prefix + "=\"" + ns + "\"" + 
        			(xsi==null?"":" " + xsi + (xsiSchemaLoc==null?"":" " + xsiSchemaLoc)) + ">";
    		endTag = "</" + prefix + ":Wrapper>";
    	}
		startTag = new String(canonicalizer.canonicalize((startTag + endTag).getBytes()));
		startTag = startTag.replaceFirst(endTag, "");
		tags[0] = startTag.getBytes();
		tags[1] = endTag.getBytes();
		return tags;
    }
    
	//used with streaming based signing. XML is parsed and message digest is calculated.
	//this methods gets a xml start tag or end tag or characters/value and it first transforms data and updates digest  
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
			//throw e;
			//************* should not ever come here - investigate if it does ************** 
	    	DocumentBuilderFactory dbfNSFalse = DocumentBuilderFactory.newInstance();
	    	dbfNSFalse.setNamespaceAware(false);
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
    
    //for an binary file, it creates base64 encoded file. if 'isCalcDigest' is true, this also calculate digest
    //digest calc is useful for while signing with Base64 transformation (not used in fatca which wraps base64 binary in xml and sign xml) 
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
	
	protected String getCanonicalizationMethod(SigXmlTransform sigXmlTransform) {
        switch(sigXmlTransform) {
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
	
	//fatca uses enveloping signing where payload is embedded within <Signature..>. payload may be enclosed in different ways:
	//<Object>, <SignatureProperty>, <SignatureProperties><SignatureProperty>
	//this method gets start and end tag to embed payload
	protected byte[][] getSigRefIdPosTags() {
    	byte[][] tags = new byte[2][];
    	String prefix = myThreadSafeData.getSignaturePrefix();
		switch(myThreadSafeData.getSigRefIdPos()) {
		case SignatureProperties:
	    	if ("".equals(prefix)) {
	    		tags[0] = ("<SignatureProperties xmlns=\"" + XMLSignature.XMLNS + "\" Id=\"" + xmlTagReferenceUriValue + "\"><SignatureProperty Target=\"#" + xmlTagSignatureIdValue + "\">").getBytes();
	    		tags[1] = "</SignatureProperty></SignatureProperties>".getBytes();
	    	} else {
	    		tags[0] = ("<" + prefix + ":SignatureProperties xmlns" + ":" + prefix + "=\"" + XMLSignature.XMLNS + "\" Id=\"" + xmlTagReferenceUriValue  + "\"><" + prefix + ":SignatureProperty Target=\"#" + xmlTagSignatureIdValue + "\">").getBytes(); 
	    		tags[1] = ("</" + prefix + ":SignatureProperty></" + prefix + ":SignatureProperties>").getBytes();
	    	}
			break;
		case SignatureProperty:
	    	if ("".equals(prefix)) {
	    		tags[0] = ("<SignatureProperty xmlns=\"" + XMLSignature.XMLNS + "\" Id=\"" + xmlTagReferenceUriValue + "\" Target=\"#" + xmlTagSignatureIdValue + "\">").getBytes();
	    		tags[1] = "</SignatureProperty>".getBytes();
	    	} else {
	    		tags[0] = ("<" + prefix + ":SignatureProperty xmlns" + ":" + prefix + "=\"" + XMLSignature.XMLNS + "\" Id=\"" + xmlTagReferenceUriValue  + "\" Target=\"#" + xmlTagSignatureIdValue + "\">").getBytes(); 
	    		tags[1] = ("</" + prefix + ":SignatureProperty>").getBytes();
	    	}
			break;
		case Object:
		default:
	    	if ("".equals(prefix)) {
	    		tags[0] = ("<Object xmlns=\"" + XMLSignature.XMLNS + "\" Id=\"" + xmlTagReferenceUriValue + "\">").getBytes();
	    		tags[1] = "</Object>".getBytes();
	    	} else {
	    		tags[0] = ("<" + prefix + ":Object xmlns" + ":" + prefix + "=\"" + XMLSignature.XMLNS + "\" Id=\"" + xmlTagReferenceUriValue + "\">").getBytes(); 
	    		tags[1] = ("</" + prefix + ":Object>").getBytes();
	    	}
			break;
		}
		return tags;
	}
	
	private class ParseXmlReturn {
		public String encoding = "UTF-8", version = "1.0", endXml = null;
	}
	
	//used with streaming based signing. XML is parsed and message digest is calculated.
	//this method parses a xml, reads a chunk of doc, say 8192 or more bytes, and transforms xml and updates digest  
	protected ParseXmlReturn calcCanonicalizedXmlMsgDigestByParsingDocChunk(String infile, MessageDigest messageDigest, 
			SigXmlTransform sigXmlTransform) throws Exception {
		logger.debug("--> calcCanonicalizedXmlMsgDigestByParsingDocChunk(). infile=" + infile + ", sigXmlTransform=" + sigXmlTransform);
    	StringBuilder sbns = new StringBuilder(), sbChunk = new StringBuilder(), parseBuf = new StringBuilder();
		String startPrefixTags, endSuffixTags, prefix, localname, nsuri, qnameS, retEndXml = null, tmpS;
		XMLStreamReader reader = null;
		ParseXmlReturn ret = new ParseXmlReturn();
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
			byte[][] sigRefIdPosTags = getSigRefIdPosTags();
			byte[] digestPrefix = sigRefIdPosTags[0], digestSuffix = sigRefIdPosTags[1];
    		messageDigest.update(digestPrefix);
    		if (digestBuf != null) {
        		digestBuf.setLength(0);
        		digestBuf.append(new String(digestPrefix));
        	}
			Canonicalizer canonicalizer = Canonicalizer.getInstance(getCanonicalizationMethod(sigXmlTransform));
	    	DocumentBuilderFactory dbfNSTrue = DocumentBuilderFactory.newInstance();
	        dbfNSTrue.setNamespaceAware(true);
	        DocumentBuilder docBuilderNSTrue = dbfNSTrue.newDocumentBuilder();
			docBuilderNSTrue.setErrorHandler(new IgnoreAllErrorHandler());
			reader = XMLInputFactory.newFactory().createXMLStreamReader(new FileInputStream(new File(infile)));
			while(!isEndDoc) {
				sbChunk.setLength(0);
				switch(reader.getEventType()) {
				case XMLStreamConstants.START_DOCUMENT:
				    ret.encoding = reader.getEncoding();
				    ret.version = reader.getVersion();
					break;
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
						} else
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
						//drop canonicalized startPrefixTags 
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
		ret.endXml = retEndXml;
		logger.debug("<-- calcCanonicalizedXmlMsgDigestByParsingDocChunk()");
		return ret;
	}

	//used with streaming based signing. XML is parsed and message digest is calculated.
	//this method parses a xml, and for every start tag or end tag or characters/value invokes processXmlFrag which transforms data and updates digest  
	protected ParseXmlReturn calcCanonicalizedXmlMsgDigestByParsingDocNoChunk(String infile, MessageDigest messageDigest, 
			SigXmlTransform sigXmlTransform) throws Exception {
		logger.debug("--> calcCanonicalizedXmlMsgDigestByParsingDocNoChunk(). infile=" + infile + ", sigXmlTransform=" + sigXmlTransform);
		String retEndXml = null;
		StringBuilder parseBuf = new StringBuilder();
		String prefix, localname, nsuri, qnameS, tmpS;
		XMLStreamReader reader = null;
		DocumentBuilder docBuilderNSTrue = null;
		ParseXmlReturn ret = new ParseXmlReturn();
		int count;
		try {
	    	DocumentBuilderFactory dbfNSTrue = DocumentBuilderFactory.newInstance();
	        dbfNSTrue.setNamespaceAware(true);
            Canonicalizer canonicalizer = Canonicalizer.getInstance(getCanonicalizationMethod(sigXmlTransform));
    		docBuilderNSTrue = dbfNSTrue.newDocumentBuilder();
			docBuilderNSTrue.setErrorHandler(new IgnoreAllErrorHandler());
			reader = XMLInputFactory.newFactory().createXMLStreamReader(new FileInputStream(new File(infile)));
			int nsCount = -1;
			String wrapperPrefix, wrapperNSUri;
			byte[][] sigRefIdPosTags = getSigRefIdPosTags();
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
				case XMLStreamConstants.START_DOCUMENT:
				    ret.encoding = reader.getEncoding();
				    ret.version = reader.getVersion();
					break;
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
					processXmlFrag(CHAR, "", tmpS, messageDigest, canonicalizer, docBuilderNSTrue, null, null);
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
			reader = null;
			messageDigest.update(digestSuffix);
			if (digestBuf != null)
	    		digestBuf.append(new String(digestSuffix));
		} finally {
			if (reader != null) try{reader.close();}catch(Exception e){}
		}
		ret.endXml = retEndXml;
		logger.debug("<-- calcCanonicalizedXmlMsgDigestByParsingDocNoChunk()");
		return ret;
	}
	
    //calculate message digest as is - no transformation. used to sign wrapped base64 binary and wrapped text document
	protected void calcXmlMsgDigestNoTransformation(String infile, MessageDigest messageDigest) throws Exception {
		logger.debug("--> calcXmlMsgDigestNoTransformation(). infile=" + infile);
		int len;
		String tmp;
		byte[][] sigRefIdPosTags = getSigRefIdPosTags();
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
    
	//not used in fatca. this calculate message digest of a text file - no transformation
	protected void calcTextMsgDigestNoTransformation(String infile, MessageDigest messageDigest) throws Exception {
		logger.debug("--> calcTextMsgDigestNoTransformation(). infile=" + infile);
		int len;
		String tmp;
		byte[][] sigRefIdPosTags = getSigRefIdPosTags();
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
    
	//creates a blank document with all signature elements. 
	//streaming signature uses this to create blank document with all signature elements, then update <DigestValue>
	//and <SignedInfo> which is then used to calculate signature value which is then used in <SignatureValue> 
    protected Document createBlankSignedDOMDocForStreamingSignature(PrivateKey sigkey, X509Certificate sigPubCert, 
    		SigDocType sigDocType, SigXmlTransform sigXmlTransform) throws Exception {
    	return createSignedDOMDoc(null, sigkey, sigPubCert, sigDocType, sigXmlTransform);
    }

    //signs a xml file using JDK signature apis (JDK only supports DOM based signing api - so file size, to sign, is limited by heap)
	protected Document createSignedDOMDoc(String infile, PrivateKey sigkey, X509Certificate sigPubCert, 
			SigDocType sigDocType, SigXmlTransform sigXmlTransform) throws Exception {
		logger.debug("--> createSignedDOMDoc(). infile=" + infile + ", sigDocType=" + sigDocType + ", sigXmlTransform=" + sigXmlTransform);
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
            	if (sigXmlTransform != SigXmlTransform.None)
               		transforms = Collections.singletonList(xmlSigFactory.newTransform(getCanonicalizationMethod(sigXmlTransform), (TransformParameterSpec) null));
            } else if (sigDocType == SigDocType.BINARY) {
                // not used in FATCA
            	transforms = Collections.singletonList(xmlSigFactory.newTransform(CanonicalizationMethod.BASE64, (TransformParameterSpec) null));
            }
        	XMLStructure content = new DOMStructure(node);
    		switch(myThreadSafeData.getSigRefIdPos()) {
    		case Object:
                xmlobj = xmlSigFactory.newXMLObject(Collections.singletonList(content), xmlTagReferenceUriValue, null, null);
            	break;
    		case SignatureProperty:
    			sigProp = xmlSigFactory.newSignatureProperty(Collections.singletonList(content), "#" + xmlTagSignatureIdValue, xmlTagReferenceUriValue);
    			sigProps = xmlSigFactory.newSignatureProperties(Collections.singletonList(sigProp), null);
    			xmlobj = xmlSigFactory.newXMLObject(Collections.singletonList(sigProps), null, null, null);
    			break;
    		case SignatureProperties:
    			sigProp = xmlSigFactory.newSignatureProperty(Collections.singletonList(content), "#" + xmlTagSignatureIdValue, null);
    			sigProps = xmlSigFactory.newSignatureProperties(Collections.singletonList(sigProp), xmlTagReferenceUriValue);
    			xmlobj = xmlSigFactory.newXMLObject(Collections.singletonList(sigProps), null, null, null);
    			break;
    		}
        	List<XMLObject> xmlObjs = Collections.singletonList(xmlobj);
            Reference sigref = xmlSigFactory.newReference("#" + xmlTagReferenceUriValue, xmlSigFactory.newDigestMethod(xmlTagDigestMethodAlgoValue, null), transforms, null, null);
            SignedInfo signedInfo = xmlSigFactory.newSignedInfo(
            		xmlSigFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
            		xmlSigFactory.newSignatureMethod(xmlTagSignatureMethodAlgoValue, null),
            		Collections.singletonList(sigref));
            KeyInfo keyInfo = null;
            if (sigPubCert != null) {
	            List<X509Certificate> list = new ArrayList<X509Certificate>();
	            list.add(sigPubCert);
	            KeyInfoFactory keyInfoFactory = xmlSigFactory.getKeyInfoFactory();
	            X509Data kv = keyInfoFactory.newX509Data(list);
	            keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(kv));
            }
            XMLSignature signature = xmlSigFactory.newXMLSignature(signedInfo, keyInfo, xmlObjs, xmlTagSignatureIdValue, null);
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

	//JDK only supports DOM based signing api - so file size, to sign, is limited by heap. this method calculate digest by reading a file stream 
	//(do not need to load entire file as required in DOM) - once digest is calculated using right transformation, rest is easy - 
	//create blank signed document, then update <DigestValue> and <SignedInfo> which is then used to calculate signature value 
	//which is then populated in <SignatureValue>. eventually write enveloping signature and payload in output file  
    protected boolean signFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sigPubCert, 
    		SigDocType sigDocType, SigXmlTransform sigXmlTransform) throws Exception {
		logger.debug("--> signFileStreaming(). infile=" + infile + ", outfile=" + outfile + ", sigDocType=" + sigDocType + ", sigXmlTransform=" + sigXmlTransform);
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
    		ParseXmlReturn parseXmlRet = null;
    		switch(sigDocType) {
    		case XML:
    	    	logger.debug("parsing xml...." + new Date());
    	    	if (myThreadSafeData.isXmlChunkStreaming())
    	    		parseXmlRet = calcCanonicalizedXmlMsgDigestByParsingDocChunk(infile, messageDigest, sigXmlTransform);
    	    	else
    	    		parseXmlRet = calcCanonicalizedXmlMsgDigestByParsingDocNoChunk(infile, messageDigest, sigXmlTransform);
	    		logger.debug("parsing xml....done. " + new Date());
				break;
    		case WRAPPEDXML:
				calcXmlMsgDigestNoTransformation(infile, messageDigest);
				break;
    		case TEXT:	// not used in FATCA
    			calcTextMsgDigestNoTransformation(infile, messageDigest);
    			break;
    		case BINARY:	// not used in FATCA
    			base64BinaryFile = UtilShared.getTmpFileName(infile, "base64");
    			bos = new BufferedOutputStream(new FileOutputStream(new File(base64BinaryFile)));
                writeBase64BinaryAndOptionallyCalcMsgDigest(infile, "\r\n", bos, true, messageDigest);
                bos.close(); bos = null;
    			break;
    		}
            Document doc = createBlankSignedDOMDocForStreamingSignature(sigkey, sigPubCert, sigDocType, sigXmlTransform);
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
            trans.setOutputProperty(OutputKeys.ENCODING, parseXmlRet.encoding);
            trans.setOutputProperty(OutputKeys.VERSION, parseXmlRet.version);
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
                writeXmlFileObjectContent(infile, bos, parseXmlRet.endXml);
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
    
    //signs a file
    protected boolean signFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sigPubCert, 
    		SigDocType sigDocType, SigXmlTransform sigXmlTransform) throws Exception {
		logger.debug("--> signFile(). infile=" + infile + ", outfile=" + outfile + ", sigDocType=" + sigDocType + ", sigXmlTransform=" + sigXmlTransform);
		BufferedOutputStream bos = null;
		boolean ret = false;
    	try {
	    	Document doc = createSignedDOMDoc(infile, sigkey, sigPubCert, sigDocType, sigXmlTransform);
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
    
    //create base64 encoded binary, wrap in xml and sign
    protected boolean wrapBinaryFileInXmlAndSign(String infile, String outfile, PrivateKey sigkey, 
    		X509Certificate sigPubCert, boolean isDOM) throws Exception {
		logger.debug("--> wrapBinaryFileInXmlAndSign(). infile=" + infile + ", outfile=" + outfile + ", isDOM=" + isDOM);
		boolean flag = false;
		String wrappedBase64BinaryFile = UtilShared.getTmpFileName(infile, "wrapped.base64.xml");
		BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(new File(wrappedBase64BinaryFile)));
		byte[][] tags = getWrapperTags();
		bos.write(tags[0]);
        writeBase64BinaryAndOptionallyCalcMsgDigest(infile, "\r\n", bos, false, null);
        bos.write(tags[1]);
        bos.close();
        if (isDOM)
        	flag = signFile(wrappedBase64BinaryFile, outfile, sigkey, sigPubCert, SigDocType.WRAPPEDXML, SigXmlTransform.None);
        else
        	flag = signFileStreaming(wrappedBase64BinaryFile, outfile, sigkey, sigPubCert, SigDocType.WRAPPEDXML, SigXmlTransform.None);
        File f = new File(wrappedBase64BinaryFile);
		if (f.exists() && !f.delete()) f.deleteOnExit();
		logger.debug("<-- wrapBinaryFileInXmlAndSign()");
		return flag;
    }

    //wrap text xml and sign
    protected boolean wrapTextFileInXmlAndSign(String infile, String outfile, PrivateKey sigkey, 
    		X509Certificate sigPubCert, boolean isDOM) throws Exception {
		logger.debug("--> wrapTextFileInXmlAndSign(). infile=" + infile + ", outfile=" + outfile + ", isDOM=" + isDOM);
		boolean flag = false;
    	int len;
        byte[] tmpBuf = new byte[myThreadSafeData.getBufSize()];
		String wrappedTextFile = UtilShared.getTmpFileName(infile, "wrapped.txt.xml");
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(new File(infile)));
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(new File(wrappedTextFile)));
		byte[][] tags = getWrapperTags();
		bos.write(tags[0]);
        while((len = bis.read(tmpBuf)) != -1)
			bos.write(tmpBuf, 0, len);
        bis.close();
        bos.write(tags[1]);
        bos.close();
        if (isDOM)
        	flag = signFile(wrappedTextFile, outfile, sigkey, sigPubCert, SigDocType.WRAPPEDXML, SigXmlTransform.None);
        else
        	flag = signFileStreaming(wrappedTextFile, outfile, sigkey, sigPubCert, SigDocType.WRAPPEDXML, SigXmlTransform.None);
        File f = new File(wrappedTextFile);
		if (f.exists() && !f.delete()) f.deleteOnExit();
		logger.debug("<-- wrapTextFileInXmlAndSign()");
		return flag;
    }

    protected boolean signFileNoWrap(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert, 
    		boolean isDom, SigDocType sigDocType) throws Exception {
    	return signFileNoWrap(infile, outfile, sigkey, sugPubCert, isDom, sigDocType, myThreadSafeData.getSigXmlTransform());
    }
    
    protected boolean signFileNoWrap(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert, 
    		boolean isDom, SigDocType sigDocType, SigXmlTransform sigXmlTransform) throws Exception {
		logger.debug("--> signFileNoWrap(). infile=" + infile + ", outfile=" + outfile + ", isDom=" + isDom + ", sigDocType=" + sigDocType + ", sigXmlTransform=" + sigXmlTransform);
    	boolean flag = false;
    	if (isDom)
    		flag = signFile(infile, outfile, sigkey, sugPubCert, sigDocType, sigXmlTransform);
    	else
    		flag = signFileStreaming(infile, outfile, sigkey, sugPubCert, sigDocType, sigXmlTransform);
    	logger.debug("<-- signFileNoWrap()");
		return flag;
    }

    //public methods - IFATCAXmlSignerExtended implementation methods
    //'ds' in <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"...> 
    public String getSignaturePrefix() {
    	return myThreadSafeData.getSignaturePrefix();
    }

    //'ds' in <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"...>
    public void setSignaturePrefix(String prefix) {
    	myThreadSafeData.setSignaturePrefix(prefix);
    }
    
    //<xyz:Wrapper ...xsi:schemaLocation="urn:xmpp:xml-element FATCA-IDES-FileWrapper-1.1.xsd">
    //'schemaLocation' value - urn:xmpp:xml-element FATCA-IDES-FileWrapper-1.1.xsd in this example
    //no need to use
    public String getWrapperXsiSchemaLoc() {
    	return myThreadSafeData.getWrapperXsiSchemaLoc();
    }
    
    //<xyz:Wrapper ...xsi:schemaLocation="urn:xmpp:xml-element FATCA-IDES-FileWrapper-1.1.xsd">
    //'schemaLocation' value - urn:xmpp:xml-element FATCA-IDES-FileWrapper-1.1.xsd in this example
    //no need to use
    public void setWrapperXsiSchemaLoc(String val) {
    	myThreadSafeData.setWrapperXsiSchemaLoc(val);
    }
    
    //<xyz:Wrapper ...xsi:schemaLocation="urn:xmpp:xml-element FATCA-IDES-FileWrapper-1.1.xsd">
    //indicate if 'schemaLocation' attribute would be present or not
    //no need to use
    public boolean isWrapperXsiSchemaLoc() {
    	return myThreadSafeData.isWrapperXsiSchemaLoc();
    }
    
    //<xyz:Wrapper ...xsi:schemaLocation="urn:xmpp:xml-element FATCA-IDES-FileWrapper-1.1.xsd">
    //indicate if 'schemaLocation' attribute would be present or not
    //no need to use
    public void setWrapperXsiSchemaLoc(boolean val) {
    	myThreadSafeData.setWrapperXsiSchemaLoc(val);
    }
    
    //<xyz:Wrapper xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"...>
    //indicate if 'xmlns:xsi' would be present or not
    //no need to use
    public boolean isWrapperXsi() {
    	return myThreadSafeData.isWrapperXsi();
    }
    
    //<xyz:Wrapper xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"...>
    //indicate if 'xmlns:xsi' would be present or not
    //no need to use
    public void setWrapperXsi(boolean val) {
    	myThreadSafeData.setWrapperXsi(val);
    }
    
    //<xyz:Wrapper xmlns:xyz="urn:xmpp:xml-element"...>
    //'xyz' in this example
    //no need to use
    public String getWrapperPrefix() {
    	return myThreadSafeData.getWrapperPrefix();
    }
    
    //<xyz:Wrapper xmlns:xyz="urn:xmpp:xml-element"...>
    //'xyz' in this example
    //no need to use
    public void setWrapperPrefix(String prefix) {
    	myThreadSafeData.setWrapperPrefix(prefix);
    }
    
    //<xyz:Wrapper xmlns:xyz="urn:xmpp:xml-element"...>
    //'urn:xmpp:xml-element' in this example
    //no need to use
    public String getWrapperNS() {
    	return myThreadSafeData.getWrapperNS();
    }
    
    //<xyz:Wrapper xmlns:xyz="urn:xmpp:xml-element"...>
    //'urn:xmpp:xml-element' in this example
    //no need to use
    public void setWrapperNS(String ns) {
    	myThreadSafeData.setWrapperNS(ns);
    }
    
    public void setBufSize(int val) {
		myThreadSafeData.setBufSize(val);
	}
	
    //sign a xml file - streaming based
    public boolean signXmlFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = false;
    	return signFileNoWrap(infile, outfile, sigkey, sugPubCert, isDom, SigDocType.XML, myThreadSafeData.getSigXmlTransform());
    }

    public boolean wrapBinaryFileInXmlAndSignStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = false;
    	return wrapBinaryFileInXmlAndSign(infile, outfile, sigkey, sugPubCert, isDom);
    }

    public boolean wrapTextFileInXmlAndSignStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = false;
    	return wrapTextFileInXmlAndSign(infile, outfile, sigkey, sugPubCert, isDom);
    }

    //sign a xml file - dom based
    public boolean signXmlFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	return signFileNoWrap(infile, outfile, sigkey, sugPubCert, true, SigDocType.XML);
    }
    
    //wrap text in xml and sign - dom based
    public boolean wrapTextFileInXmlAndSign(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = true;
    	return wrapTextFileInXmlAndSign(infile, outfile, sigkey, sugPubCert, isDom);
    }

    //create baed64 encoded binary, wrap in xml and sign - dom based
    public boolean wrapBinaryFileInXmlAndSign(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = true;
    	return wrapBinaryFileInXmlAndSign(infile, outfile, sigkey, sugPubCert, isDom);
    }

    //<Object Id="FATCA">[payload]</Object> or
    //<Object><SignatureProperties><SignatureProperty Id="FATCA">[payload]</SignatureProperty></SignatureProperties></Object> or 
    //<Object><SignatureProperties Id="FATCA"><SignatureProperty Target="#SignatureId">[payload]</SignatureProperty></SignatureProperties></Object>
    //returns Object|SignatureProperty|SignatureProperties
	public String getSigRefIdPos() {
		SigRefIdPos sigRefIdPos = myThreadSafeData.getSigRefIdPos();
		switch(sigRefIdPos) {
		case Object:
			return "Object";
		case SignatureProperty:
			return "SignatureProperty";
		case SignatureProperties:
			return "SignatureProperties";
		}
		return null;
	}
	
	//Object|SignatureProperty|SignatureProperties
	public void setSigRefIdPos(String sigRefIdPos) throws Exception {
		if ("Object".equalsIgnoreCase(sigRefIdPos))
			myThreadSafeData.setSigRefIdPos(SigRefIdPos.Object);
		else if ("SignatureProperty".equalsIgnoreCase(sigRefIdPos))
			myThreadSafeData.setSigRefIdPos(SigRefIdPos.SignatureProperty);
		else if ("SignatureProperties".equalsIgnoreCase(sigRefIdPos))
			myThreadSafeData.setSigRefIdPos(SigRefIdPos.SignatureProperties);
		else
			throw new Exception("invalid sigRefIdPos=" + sigRefIdPos + ". Valid values are Object|SignatureProperty|SignatureProperties");
	}

	//Inclusive: <Transforms><Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></Transforms>
	//InclusiveWithComments: <Transforms><Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/></Transforms>
	//Exclusive: <Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>
	//ExclusiveWithComments: <Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/></Transforms>
	public String getSigXmlTransform() {
		SigXmlTransform sigXmlTransform = myThreadSafeData.getSigXmlTransform();
		switch(sigXmlTransform) {
		case Inclusive:
			return "Inclusive";
		case InclusiveWithComments:
			return "InclusiveWithComments";
		case Exclusive:
			return "Exclusive";
		case ExclusiveWithComments:
			return "ExclusiveWithComments";
		case None:
			return "None";
		}
		return null;
	}

	//Inclusive|InclusiveWithComments|Exclusive|ExclusiveWithComments|None
	public void setSigXmlTransform(String sigXmlTransform) throws Exception {
		if ("Inclusive".equalsIgnoreCase(sigXmlTransform))
			myThreadSafeData.setSigXmlTransform(SigXmlTransform.Inclusive);
		else if ("InclusiveWithComments".equalsIgnoreCase(sigXmlTransform))
			myThreadSafeData.setSigXmlTransform(SigXmlTransform.InclusiveWithComments);
		else if ("Exclusive".equalsIgnoreCase(sigXmlTransform))
			myThreadSafeData.setSigXmlTransform(SigXmlTransform.Exclusive);
		else if ("ExclusiveWithComments".equalsIgnoreCase(sigXmlTransform))
			myThreadSafeData.setSigXmlTransform(SigXmlTransform.ExclusiveWithComments);
		else if ("None".equalsIgnoreCase(sigXmlTransform))
			myThreadSafeData.setSigXmlTransform(SigXmlTransform.None);
		else throw new Exception("invalid sigXmlTransform=" + sigXmlTransform + ". Valid values are Inclusive|InclusiveWithComments|Exclusive|ExclusiveWithComments|None");
	}

	//flag XmlChunkStreaming - default to true
	public void setXmlChunkStreaming(boolean val) {
		myThreadSafeData.setXmlChunkStreaming(val);
	}

	//flag XmlChunkStreaming - default to true
	public boolean isXmlChunkStreaming() {
		return myThreadSafeData.isXmlChunkStreaming();
	}

	//chunk size if XmlChunkStreaming is true - default is 8092. XmlChunk is used with streaming based signing to calculate message digest
	public int getXmlChunkStreamingSize() {
		return myThreadSafeData.getXmlChunkStreamingSize();
	}
	
	public void setXmlChunkStreamingSize(int val) {
		myThreadSafeData.setXmlChunkStreamingSize(val);
	}

	//digestBuf is for debugging
	public StringBuilder getDigestBuf() {
		return digestBuf;
	}

	//digestBuf is for debugging
	public void setDigestBuf(StringBuilder digestBuf) {
		this.digestBuf = digestBuf;
	}

	//isValidateAllSignature is for debugging
	public boolean isValidateAllSignature() {
		return isValidateAllSignature;
	}

	//isValidateAllSignature is for debugging
	public void setValidateAllSignature(boolean isValidateAllSignature) {
		this.isValidateAllSignature = isValidateAllSignature;
	}

	//isValidationSuccess is for debugging
	public Boolean isValidationSuccess() {
		return isValidationSuccess;
	}

	//isValidationSuccess is for debugging
	public void setValidationSuccess(Boolean isValidationSuccess) {
		this.isValidationSuccess = isValidationSuccess;
	}

    //not used in FATCA
    public boolean signTextFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	return signFileNoWrap(infile, outfile, sigkey, sugPubCert, true, SigDocType.TEXT, SigXmlTransform.None);
    }

    //not used in FATCA
    public boolean signBinaryFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	return signFileNoWrap(infile, outfile, sigkey, sugPubCert, true, SigDocType.BINARY, SigXmlTransform.None);
    }
    
    // not used in FATCA
    public boolean signTextFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = false;
    	return signFileNoWrap(infile, outfile, sigkey, sugPubCert, isDom, SigDocType.TEXT, SigXmlTransform.None);
    }

    // not used in FATCA
    public boolean signBinaryFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = false;
    	return signFileNoWrap(infile, outfile, sigkey, sugPubCert, isDom, SigDocType.BINARY, SigXmlTransform.None);
    }
}
