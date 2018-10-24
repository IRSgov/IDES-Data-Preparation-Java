package impl;

import impl.Signer.SignedDocument.ReferenceInfo;
import intf.ISignatureVerifier;
import intf.ISigner;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.RandomAccessFile;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Stack;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicInteger;

import javax.xml.crypto.Data;
import javax.xml.crypto.NodeSetData;
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
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
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
public class Signer implements ISigner {
	protected Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

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
	
    //<Object Id="ObjRefId">[payload]</Object> or
    //<Object><SignatureProperties><SignatureProperty Id="ObjRefId">[payload]</SignatureProperty></SignatureProperties></Object> or 
    //<Object><SignatureProperties Id="ObjRefId"><SignatureProperty Target="#SignatureId">[payload]</SignatureProperty></SignatureProperties></Object>
	public enum SigRefIdPos {Object, SignatureProperty, SignatureProperties}
	
	//transformation/canonicalization to use for signing. transformation affect digest value and thus signature value 
	//Inclusive: <Transforms><Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></Transforms>
	//InclusiveWithComments: <Transforms><Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/></Transforms>
	//Exclusive: <Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>
	//ExclusiveWithComments: <Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/></Transforms>
	public enum SigXmlTransform {Inclusive, InclusiveWithComments, Exclusive, ExclusiveWithComments, None};
	
	public enum SigDocType {XML, 
		WRAPPEDXML, //binary (base64 encoded) and text files are wrapped in xml before signing 
		TEXT,	//not used
 		BINARY	//not used, uses Base64 transformation
	};

	//for debug only
	public byte[] digestBuf  = null;
	
	//all these variables are THREAD UNSAFE
	protected boolean isVerifyAllSignature = false;
	
	protected String signaturePrefix = "ds";
	//base64 binary and text are wrapped in xml before signing
	protected String wrapperPrefix = "";
	protected String wrapperNS = "urn:xmpp:xml-element";
	protected String wrapperXsi = "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"";
	protected String wrapperXsiSchemaLoc = "xsi:schemaLocation=\"urn:xmpp:xml-element FileWrapper-1.1.xsd\"";
	protected boolean useWrapperXsi = false;
	protected boolean useWrapperXsiSchemaLoc = false;

	protected SigRefIdPos sigRefIdPos = SigRefIdPos.Object;
	protected SigXmlTransform sigXmlTransform = SigXmlTransform.Inclusive;
	
	protected ISignatureVerifier signatureVerifier = null;
	
	protected boolean isExcludeKeyInfoFromSignature = false;
    //used if isGenRandomRefUri = false. useful for debugging
    protected AtomicInteger refUriGenId = new AtomicInteger(0);

    protected boolean isAddSignaturePropTimestamp = false;
    protected boolean isSignKeyInfo = true;
    protected boolean isGenRandomRefUri = true;

	protected class XmlDeclaration {
		public String encoding = "UTF-8", version = "1.0"; boolean isStandalone = false;
		public String toXmlDeclStr() {
			return "<?xml version=\""+(version==null?"1.0":version)+"\" encoding=\""+(encoding==null?"UTF-8":encoding)+"\" standalone=\""+(isStandalone?"yes":"no")+"\"?>";
		}
	}
	
	public Signer() {
		if (!Init.isInitialized())
			Init.init();
    }
	
	//base64 binary and text are wrapped in xml before signing
	//returns start and end wrapper tags. Sample:<Wrapper xmlns="urn:xmpp:xml-element"> and </Wrapper>
	protected String[] getWrapperTags() throws Exception {
    	String ns = wrapperNS, prefix = wrapperPrefix, xsi = null, xsiSchemaLoc = null;
    	boolean isXsi = useWrapperXsi, isXsiSchemaLoc = useWrapperXsiSchemaLoc;
    	if (isXsi) {
    		xsi = wrapperXsi;
    		if (isXsiSchemaLoc)
    			xsiSchemaLoc = wrapperXsiSchemaLoc;
    	}
    	if (prefix == null)
    		prefix = "";
    	if ("".equals(ns) && !"".equals(prefix))
    		throw new Exception("non-empty wrapperPrefix not allowed for empty wrapperNS");
    	String[] tags = new String[2];
    	String startTag, endTag;
    	//DO NOT CHANGE CanonicalizationMethod.INCLUSIVE
		Canonicalizer canonicalizer = Canonicalizer.getInstance(CanonicalizationMethod.INCLUSIVE);
    	if ("".equals(prefix)) {
    		//<Wrapper xmlns="urn:xmpp:xml-element" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:xmpp:xml-element FileWrapper-1.1.xsd">
    		startTag = "<Wrapper xmlns=\"" + ns + "\"" + (xsi==null?"":" " + xsi + (xsiSchemaLoc==null?"":" " + xsiSchemaLoc)) + ">";
    		endTag = "</Wrapper>";
    	} else {
    		//<xyz:Wrapper xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xyz="urn:xmpp:xml-element" xsi:schemaLocation="urn:xmpp:xml-element FileWrapper-1.1.xsd">
        	startTag = "<" + prefix + ":Wrapper xmlns" + ":" + prefix + "=\"" + ns + "\"" + 
        			(xsi==null?"":" " + xsi + (xsiSchemaLoc==null?"":" " + xsiSchemaLoc)) + ">";
    		endTag = "</" + prefix + ":Wrapper>";
    	}
		startTag = new String(canonicalizer.canonicalize((startTag + endTag).getBytes()));
		startTag = startTag.replaceFirst(endTag, "");
		tags[0] = startTag;
		tags[1] = endTag;
		return tags;
    }
    
    //for an binary file, it creates base64 encoded file. if 'isCalcDigest' is true, this also calculate digest
    //digest calc is useful for while signing with Base64 transformation (not used) 
    protected void writeBase64BinaryAndOptionallyCalcMsgDigest(String infile, String newline, Writer writer, 
			boolean isCalcDigest, MessageDigest md) throws Exception {
		logger.debug("--> writeBase64BinaryAndOptionallyCalcMsgDigest(). infile=" + infile);
		if (isCalcDigest && md == null)
			throw new Exception("messageDigest must not be null if isCalcDigest=true");
		BufferedInputStream bis = null;
		try {
			bis = new BufferedInputStream(new FileInputStream(new File(infile)));
			int len, offset = 0, nextoffset, lastlinelen = 0;
			//min buf size is 3
			byte[] buf = new byte[UtilShared.defaultBufSize < 3 ? 3 : UtilShared.defaultBufSize];
			byte[] tmpBuf;
			while((len = bis.read(buf, offset, buf.length - offset)) != -1) {
				if (isCalcDigest)
					md.update(buf, offset, len);
				//3 binary bytes convert to 4 Base64 bytes - so encode multiple of 3 bytes together until the end   
				nextoffset = (offset+len) % 3;
				tmpBuf = new byte[offset+len-nextoffset];
				System.arraycopy(buf, 0, tmpBuf, 0, offset+len-nextoffset);
				for (int i = 0; i < nextoffset; i++)
					buf[i] = buf[offset+len-nextoffset+i];
				offset = nextoffset;
				lastlinelen = writeEncodedBinary(lastlinelen, tmpBuf, newline, writer);
			}
			if (offset > 0) {
				tmpBuf = new byte[offset];
				System.arraycopy(buf, 0, tmpBuf, 0, offset);
				writeEncodedBinary(lastlinelen, tmpBuf, newline, writer);
			}
			bis.close();
			bis = null;
		} finally {
			if (bis != null)try{bis.close();}catch(Throwable t){}
		}
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
	
	protected void updateDigestWithXmlChunk(StringBuilder parseBuf, MessageDigest messageDigest, Stack<XmlTag> stackStartTag, 
			Stack<XmlTag> stackChunkStartTag, Stack<XmlTag> stackChunkEndTag, Canonicalizer canonicalizer, DocumentBuilder docBuilderNSTrue, 
			String digestPrefixStr, String digestSuffixStr) throws Exception {
    	//stackChunkStartTag has start tags whose end tags are not in chunk
    	//stackChunkEndTag has end tags whose start tags are not in chunk
    	int startPrefixTagCount = 0, pos;
    	int startTagToAddCount = stackStartTag.size() - stackChunkStartTag.size();
    	String startPrefixTags = "", endSuffixTags = "", prefix, suffix;
    	XmlTag tag;
    	byte[] tmpbuf;
    	//add end tags, newest to oldest to match xml structure, to xml chunk for transformation
    	while (!stackChunkStartTag.empty()) {
    		//stackChunkStartTag - 0=<MessageSpec>, 1=<TAG>....add suffix </TAG></MessageSpec>
    		tag = stackChunkStartTag.pop();
    		//corresponding start tag exists in chunk
    		endSuffixTags = endSuffixTags + tag.getEndTag();
    	}
    	//add start tags, newest to oldest to match xml structure, to xml chunk for transformation
    	while (!stackChunkEndTag.empty()) {
    		//stackChunkEndTag - 0=<Address>, 1=<AddressFix>....meaning parseBuf has </AddressFix></Address>
    		//add prefix <Address><AddressFix>
    		startPrefixTagCount++;
    		tag = stackChunkEndTag.pop();
    		startPrefixTags = startPrefixTags + tag.getStartTag();
    		//corresponding end tag exists in chunk
    	}
    	//add tags, prefix and suffix, present in stackStartTag as they may have NS (namespace) defined
    	//even if a tag in stackStartTag has no NS defined, we need them because of correct transformation, mainly for 'Exclusive' transformation 
    	//stackStartTag - 0=<OUTERTAG>, 1=<MessageSpec> add prefix=<OUTERTAG><MessageSpec> and suffix=</MessageSpec></OUTERTAG>
    	prefix = suffix = "";
    	for (int i = 0; i < startTagToAddCount; i++) {
    		tag = stackStartTag.get(i);
    		//do not restrict to tags with ns only - Exclusive transformation would fail
			startPrefixTagCount++;
			prefix = prefix + tag.getStartTag();
			suffix = tag.getEndTag() + suffix;
    	}
    	startPrefixTags = prefix + startPrefixTags;
    	endSuffixTags = endSuffixTags + suffix;
    	startPrefixTags = digestPrefixStr + startPrefixTags;
    	//for prefix with digestPrefixStr
    	//<Object> and <SignatureProperty> has 1 prefix tag while <SignatureProperties><SignatureProperty> has 2
    	pos = 0;
    	while ((pos = digestPrefixStr.indexOf(">", pos + 1)) > 0)
   			startPrefixTagCount++;
    	endSuffixTags += digestSuffixStr;
    	String modifiedval = startPrefixTags + parseBuf.toString() + endSuffixTags;
		logger.trace("to transform str=" + modifiedval);
    	Document doc = docBuilderNSTrue.parse(new InputSource(new StringReader(modifiedval)));
		String digestval = new String(canonicalizer.canonicalizeSubtree(doc));
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
		logger.trace("digestval=" + digestval);
		tmpbuf = digestval.getBytes();
		messageDigest.update(tmpbuf);
		if (digestBuf != null) 
			digestBuf = UtilShared.append(digestBuf, tmpbuf);
		parseBuf.setLength(0);
    	stackChunkStartTag.clear();
    	stackChunkEndTag.clear();
	}
	
	//this method is used by streaming based signing methods to calculate digest of a xml with required transformation
	//it chunks xml, add required prefix/suffix, apply transformation and calculate transformed chunk digest (after dropping prefix/suffix used for transformation)
	//this technique of calculating digest with chunks can be used to sign large file which may not be possible with JDK DOM based signing technique as that (DOM)
	//requires the entire document to be read in memory before signing
	protected void calcCanonicalizedXmlMsgDigestByParsingDocChunk(Writer writer, ReferenceInfo ri, 
			SigXmlTransform sigXmlTransform) throws Exception {
		logger.debug("--> calcCanonicalizedXmlMsgDigestByParsingDocChunk(). infile=" + ri.infile + ", sigXmlTransform=" + sigXmlTransform);
    	StringBuilder sbElem = new StringBuilder(), parseBuf = new StringBuilder();
		String prefix, localname, nsuri, qnameS, tmpS;
		XMLStreamReader reader = null;
		FileInputStream fis = null;

		//We piggyback transformation to existing DOM based apis
		//As we are using streaming based apis to read partial xml and calculate digest after necessary transformation, we need to keep track start/end tags
		//Partial xml frags may not be in valid xml format (missing start/end tags) and we need to add missing start/end tags 
		//to form valid xml in order to apply transformation. 
		//These Stack vars are used keep track missing start/end tags of an xml frags 

		//start tag are pushed in stackStartTag and popped in matching end tags
		//start tags within a chunk are pushed in stackChunkStartTag and popped in matching end tags
		//contents of stackChunkStartTag are the tags defined in the chunk whose end tags not present in the chunk
		//while processing chunk, for each stackChunkStartTag elements, a end tag suffix is created
		//stackChunkEndTag contains end tags in chunk for missing start tag in chunk. 
		//while processing chunk, for each stackChunkEndTag elements, a start tag prefix is created
		Stack<XmlTag> stackStartTag = new Stack<XmlTag>(), stackChunkStartTag = new Stack<XmlTag>(), stackChunkEndTag = new Stack<XmlTag>(); 
		int nscount, count;
		boolean isEndDoc = false;
		QName qname;
		XmlTag tag, lastStartTag;
		try {
			String[] arr = ri.getReferencePrefixAndSuffix();
			String sigRefIdPrefix = arr[0];
			String sigRefIdSuffix = arr[1];
    		ri.md.update(sigRefIdPrefix.getBytes());
    		if (digestBuf != null) {
        		digestBuf = new byte[0];
        		digestBuf = UtilShared.append(digestBuf, sigRefIdPrefix.getBytes());
        	}
			Canonicalizer canonicalizer = Canonicalizer.getInstance(getCanonicalizationMethod(sigXmlTransform));
	    	DocumentBuilderFactory dbfNSTrue = DocumentBuilderFactory.newInstance();
	        dbfNSTrue.setNamespaceAware(true);
	        DocumentBuilder docBuilderNSTrue = dbfNSTrue.newDocumentBuilder();
			docBuilderNSTrue.setErrorHandler(new IgnoreAllErrorHandler());
			//do not use FileReader as reader breaks if xml starts with utf8 BOM, EFBBBF (editor such as notepad urf8 encoding uses BOM)
			fis = new FileInputStream(new File(ri.infile));
			reader = XMLInputFactory.newFactory().createXMLStreamReader(fis);
			while(!isEndDoc) {
				sbElem.setLength(0);
				switch(reader.getEventType()) {
				case XMLStreamConstants.START_ELEMENT:
					qname = reader.getName();
					lastStartTag = new XmlTag(qname);
					stackStartTag.push(lastStartTag);
					stackChunkStartTag.push(lastStartTag);
					prefix = reader.getPrefix();
					localname = reader.getLocalName();
					qnameS = ((prefix == null || "".equals(prefix)) ? "" : prefix + ":") + localname;
					sbElem.append('<');
				    sbElem.append(qnameS);
					nscount = reader.getNamespaceCount();
					List<String> sortedList = null; String defaultNs = null; String[] sortedArr = null;
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
								if (sortedList == null)
									sortedList = new ArrayList<String>();
								sortedList.add(tmpS + "=" + nsuri);
							}
						}
					}
					if (defaultNs != null) {
						sbElem.append(" ");
						sbElem.append(defaultNs);
					}
					if (sortedList != null) {
						sortedArr = sortedList.toArray(new String[0]);
						//probably sorted name spaces may not be needed as transformation (most likely) sort them anyway
						Arrays.sort(sortedArr);
						for (int i = 0; i < sortedArr.length; i++) {
							sbElem.append(" ");
							sbElem.append(sortedArr[i]);
							if ("".equals(lastStartTag.nsuri))
								lastStartTag.nsuri = sortedArr[i];
							else
								lastStartTag.nsuri = lastStartTag.nsuri + " " + sortedArr[i];
						}
					}
					count = reader.getAttributeCount();
					if (count > 0) {
						sortedArr = new String[count];
						for (int i = 0; i < count; i++) {
							tmpS = reader.getAttributeValue(i).replace("'", "&apos;").replace("\"", "&quot;");;
							localname = reader.getAttributeLocalName(i);
							prefix = reader.getAttributePrefix(i);
							sortedArr[i] = ((prefix == null || "".equals(prefix)) ? localname : (prefix + ":" + localname)) + "=\"" + tmpS + "\"";
						}
						//probably sorted attributes may not be needed as transformation (most likely) sort them anyway
						Arrays.sort(sortedArr);
						for (int i = 0; i < sortedArr.length; i++) {
							sbElem.append(" ");
							sbElem.append(sortedArr[i]);
						}
					}
					sbElem.append(">");
					parseBuf.append(sbElem.toString());
					writer.write(sbElem.toString());
			    	break;
				case XMLStreamConstants.CHARACTERS:
					tmpS = reader.getText();
					//replace predefined xml entity [<, >, &] with escape sequence. note [', "] are not allowed in attribute only
					tmpS = tmpS.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
					parseBuf.append(tmpS);
					writer.write(tmpS);
					break;
				case XMLStreamConstants.COMMENT:
					sbElem.append("<!--");
					sbElem.append(reader.getText());
					sbElem.append("-->");
					writer.write(sbElem.toString());
					break;
				case XMLStreamConstants.END_ELEMENT:
					tag = stackStartTag.pop();
				    if (stackChunkStartTag.empty())
				    	stackChunkEndTag.push(tag); //missing matching start tag in chunk so push tag in stackChunkEndTag
				    else
				    	stackChunkStartTag.pop(); //matching end tag found in chunk so pop tag from stackChunkStarttag
				    qname = reader.getName();
					prefix = reader.getPrefix();
					localname = reader.getLocalName();
					qnameS = ((prefix == null || "".equals(prefix)) ? "" : prefix + ":") + localname;
					sbElem.append("</" + qnameS + ">");
				    writer.write(sbElem.toString());
				    parseBuf.append(sbElem.toString());
				    if (parseBuf.length() > UtilShared.defaultChunkStreamingSize)
				    	updateDigestWithXmlChunk(parseBuf, ri.md, stackStartTag, stackChunkStartTag, stackChunkEndTag, 
				    			canonicalizer, docBuilderNSTrue, sigRefIdPrefix, sigRefIdSuffix);
					break;
				case XMLStreamConstants.END_DOCUMENT:
					isEndDoc = true;
					updateDigestWithXmlChunk(parseBuf, ri.md, stackStartTag, stackChunkStartTag, stackChunkEndTag, 
			    			canonicalizer, docBuilderNSTrue, sigRefIdPrefix, sigRefIdSuffix);
					break;
				}
				if (reader.hasNext())
					reader.next();
				else if (!isEndDoc)
					throw new Exception("bug. no more element to reach while not end of document");
			}
			reader.close();
			reader = null;
			fis.close();
			fis = null;
			ri.md.update(sigRefIdSuffix.getBytes());
			if (digestBuf != null)
	    		digestBuf = UtilShared.append(digestBuf, sigRefIdSuffix.getBytes());
		} catch(Exception e) {
			e.printStackTrace();
			logger.error("infile=" + ri.infile + ", exception msg=" + e.getMessage());
			throw e;
		} finally {
			if (reader != null) try{reader.close();}catch(Throwable t){}
			if (fis != null) try{fis.close();}catch(Throwable t){}
		}
		logger.debug("<-- calcCanonicalizedXmlMsgDigestByParsingDocChunk()");
	}

    //calculate message digest as is - no transformation. used to sign wrapped base64 binary and wrapped text document
	protected void calcXmlMsgDigestNoTransformation(ReferenceInfo ri) throws Exception {
		logger.debug("--> calcXmlMsgDigestNoTransformation(). infile=" + ri.infile);
		int len;
		String[] tmparr = ri.getReferencePrefixAndSuffix();
		String sigRefIdPrefix = tmparr[0];
		String sigRefIdSuffix = tmparr[1];
		byte[] digestPrefix = sigRefIdPrefix.getBytes(), digestSuffix = sigRefIdSuffix.getBytes();
		ri.md.update(digestPrefix);
		if (digestBuf != null) {
    		digestBuf = new byte[0];
    		digestBuf = UtilShared.append(digestBuf, digestPrefix);
    	}
    	BufferedReader br = null;
    	try {
	    	br = new BufferedReader(new FileReader(new File(ri.infile)));
			char[] buf = new char[UtilShared.defaultBufSize], buftostrip = null, tmpbuf = null;
			boolean strippedXmlDecl = false;
			while((len = br.read(buf)) != -1) {
				if (!strippedXmlDecl) {
					if (buftostrip == null) {
						buftostrip = new char[len];
						System.arraycopy(buf, 0, buftostrip, 0, buftostrip.length);
					} else {
						tmpbuf = new char[buftostrip.length+len];
						System.arraycopy(buftostrip, 0, tmpbuf, 0, buftostrip.length);
						System.arraycopy(buf, 0, tmpbuf, buftostrip.length, len);
						buftostrip = tmpbuf;
					}
					tmpbuf = UtilShared.stripXmlHeader(buftostrip);
					if (tmpbuf == null)
						continue;
					strippedXmlDecl = true;
					tmpbuf = UtilShared.stripCR(tmpbuf, tmpbuf.length);
				} else
					tmpbuf = UtilShared.stripCR(buf, len);
	    		if (digestBuf != null)
		    		digestBuf = UtilShared.append(digestBuf, new String(tmpbuf));
				ri.md.update(new String(tmpbuf).getBytes());
			}
			br.close();
			br = null;
			ri.md.update(digestSuffix);
			if (digestBuf != null)
	    		digestBuf = UtilShared.append(digestBuf, digestSuffix);
    	} finally {
    		if (br != null) try{br.close();}catch(Throwable t){}
    	}
		logger.debug("<-- calcXmlMsgDigestNoTransformation()");
    }
    
	//not used in this packaging. this calculate message digest of a text file - no transformation
	protected void calcTextMsgDigestNoTransformation(ReferenceInfo ri) throws Exception {
		logger.debug("--> calcTextMsgDigestNoTransformation(). infile=" + ri.infile);
		int len;
		String tmp;
		String[] tmparr = ri.getReferencePrefixAndSuffix();
		String sigRefIdPrefix = tmparr[0];
		String sigRefIdSuffix = tmparr[1];
		byte[] digestPrefix = sigRefIdPrefix.getBytes(), digestSuffix = sigRefIdSuffix.getBytes();
		ri.md.update(digestPrefix);
		if (digestBuf != null) {
    		digestBuf = new byte[0];
    		digestBuf = UtilShared.append(digestBuf, digestPrefix);
    	}
    	BufferedReader br = null;
    	try {
	    	br = new BufferedReader(new FileReader(new File(ri.infile)));
			char[] tmpBuf = new char[UtilShared.defaultBufSize];
			while((len = br.read(tmpBuf)) != -1) {
				tmp = new String(tmpBuf, 0, len);
				if (tmpBuf[len-1] == '\r') {
					len = br.read();
					if (len != -1)
						tmp = tmp + (char)len;
				}
				//process end of line per xml spec; replace \r\n with \n and all \r (which do not followed by \n) with \n
				tmp = tmp.replace("\r\n", "\n").replace("\r", "\n");
				//enveloping signature; so <>& not allowed; digest must be calculated after replacing &<>
				tmp = tmp.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
				if (digestBuf != null)
		    		digestBuf = UtilShared.append(digestBuf, tmp.getBytes());
				ri.md.update(tmp.getBytes());
			}
			br.close();
			ri.md.update(digestSuffix);
			if (digestBuf != null)
	    		digestBuf = UtilShared.append(digestBuf, digestSuffix);
    	} finally {
    		if (br != null) try{br.close();}catch(Throwable t){}
    	}
		logger.debug("<-- calcTextMsgDigestNoTransformation()");
    }
	
	protected String getInclusiveTransformedElemXml(Element elem) throws Exception {
		byte[] xmlB = UtilShared.getNodeXml(elem).getBytes();
		Canonicalizer canonicalizer = Canonicalizer.getInstance(CanonicalizationMethod.INCLUSIVE);
		String xml = new String(canonicalizer.canonicalize(xmlB)).replace("\r\n", "\n");
		return xml;
	}
	
	protected List<XMLStructure> getSignaturePropertyList(Document doc, SigDocType sigDocType) throws Exception {
		List<XMLStructure> list = new ArrayList<XMLStructure>();
		if (isAddSignaturePropTimestamp && sigDocType != SigDocType.BINARY) {
			SimpleDateFormat sdf = new SimpleDateFormat("dd-MMM-yyyy'T'HH:mm:ss.SSS'Z'"); 
			sdf.setTimeZone(TimeZone.getTimeZone(ZoneOffset.UTC));
			Element tselem;
			if (signaturePrefix == null || "".equals(signaturePrefix))
				tselem = doc.createElementNS(XMLSignature.XMLNS, "Timestamp");
			else
				tselem = doc.createElementNS(XMLSignature.XMLNS, signaturePrefix + ":Timestamp");
			tselem.appendChild(doc.createTextNode(sdf.format(new Date())));
			list.add(new DOMStructure(tselem));
			//may add additional properties in future
		}
		return list;
	}
    
    public class SignedDocument {
    	public Document doc = null;
    	public List<ReferenceInfo> refInfos = new ArrayList<ReferenceInfo>();
    	public String[] getXmlChunkBeforeAndAfterStrmSigFakeStr() throws Exception {
    		List<String> list = new ArrayList<String>();
    		//DO NOT CHANGE CanonicalizationMethod.INCLUSIVE in SignedInfo
    		String docXml = getInclusiveTransformedElemXml(doc.getDocumentElement());
    		String tmp = docXml;
    		ReferenceInfo ri;
    		int pos = -1;
    		for (int i = 0; i < refInfos.size(); i++) {
    			ri = refInfos.get(i);
    			if (ri.strmSigFakeStr == null)
    				throw new Exception("bug. strmSigFakeStr is null");
    			pos = tmp.indexOf(ri.strmSigFakeStr);
    			if (pos == -1)
    				throw new Exception("bug. " + ri.strmSigFakeStr + " not found in " + tmp + ". docXml=" + docXml);
    			list.add(tmp.substring(0, pos));
    			tmp = tmp.substring(pos + ri.strmSigFakeStr.length());
    		}
    		if ("".equals(tmp))
    			throw new Exception("bug. invalid docXml, tmp must not be empty here, docXml=" + docXml);
   			list.add(tmp);
   			String[] arr = list.toArray(new String[]{});
   			return arr;
    	}
    	//ignore KeyInfo
    	public class ReferenceInfo {
    		public String infile = null;
    		public Element referencedElem = null;
    		public Element referenceElem = null;
    		public String refUriVal = null;
    		public String strmSigFakeStr = null;
    		public MessageDigest md = null;
    		private String digest = null;
    		public ReferenceInfo() throws Exception {
                if (defaultMessageDigestProvider != null)
        			md = MessageDigest.getInstance(MESSAGE_DIGEST_ALGO, defaultMessageDigestProvider);
        		else
        			md = MessageDigest.getInstance(MESSAGE_DIGEST_ALGO);
    		}
    		public String digest() {
    			if (digest == null)
    				digest = Base64.encode(md.digest());
    			return digest;
    		}
    		public String[] getReferencePrefixAndSuffix() throws Exception {
                if (referencedElem == null)
                	referencedElem = UtilShared.getElementWithASpecificAttribute(doc.getDocumentElement(), "Id", refUriVal);
                if (referencedElem == null)
                	throw new Exception("Invalid document structure. Missing <TAG Id=" + refUriVal + ">");
                //DO NOT CHANGE CanonicalizationMethod.INCLUSIVE in SignedInfo
                String refIdXml = getInclusiveTransformedElemXml(referencedElem);
        		int pos = refIdXml.indexOf(strmSigFakeStr);
    	    	String sigRefIdPrefix = refIdXml.substring(0, pos);
    	    	String sigRefIdSuffix = refIdXml.substring(pos + strmSigFakeStr.length());
    	    	String[] arr = new String[] {sigRefIdPrefix, sigRefIdSuffix};
                return arr;
    		}
    		
    	}
    }
    
    protected String getStrmSigFakeStr() {
    	StringBuilder sb = new StringBuilder(UtilShared.genUniqueRandomId());
    	//8dda9766-b0dd-4853-8669-820da5f948bf@194494468
    	while (sb.length() < 64)
    		sb.append(UtilShared.genUniqueRandomId());
    	String strmSigFakeStr = Base64.encode(sb.toString().getBytes()).replace("\r", "").replace("\n", ""); //cover binary transform
    	return strmSigFakeStr;
    }
    
    protected String prettyNames(String[] infiles) {
    	StringBuilder sb = new StringBuilder();
    	for (int i = 0; i < infiles.length; i++) {
    		if (i > 0)
    			sb.append(",");
    		sb.append(infiles[i]);
    	}
    	return sb.toString();
    }

    //signs a xml file using JDK signature apis (JDK only supports DOM based signing api - so file size, to sign, is limited by heap)
	protected SignedDocument createSignedDOMDoc(String[] infiles, PrivateKey sigkey, X509Certificate sigPubCert, 
			SigDocType sigDocType, SigXmlTransform sigXmlTransform, boolean isNSAware, boolean isBlankDoc) throws Exception {
		logger.debug("--> createSignedDOMDoc(). infiles=" + prettyNames(infiles) + ", sigDocType=" + sigDocType + ", sigXmlTransform=" + sigXmlTransform);
		SignedDocument sd = new SignedDocument();
    	BufferedInputStream bis = null;
        int len;
    	List<XMLObject> xmlobjs = null;
    	List<Transform> transforms = null;
        SignatureProperty sigProp;
        SignatureProperties sigProps;
        Document doc = null;
        Node[] nodes = null;
    	ReferenceInfo ri = null;
    	XMLObject xmlobj = null;
    	try {
    		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    		dbf.setNamespaceAware(isNSAware);
            DocumentBuilder docBuilder = dbf.newDocumentBuilder();
            docBuilder.setErrorHandler(new IgnoreAllErrorHandler());
            nodes = new Node[infiles.length];
            for (int i = 0; i < infiles.length; i++) {
            	ri = sd.new ReferenceInfo();
            	sd.refInfos.add(ri);
            	ri.infile = infiles[i];
            	doc = docBuilder.newDocument();
            	if (isBlankDoc) {
	            	ri.strmSigFakeStr = getStrmSigFakeStr();
	            	nodes[i] = doc.createTextNode(ri.strmSigFakeStr);
	        	} else {
                	//DOM signature
                    switch(sigDocType) {
                    case XML:
                    case WRAPPEDXML:
                    	bis = new BufferedInputStream(new FileInputStream(new File(infiles[i])));
                    	doc = docBuilder.parse(bis);
                    	bis.close();
                    	bis = null;
                    	nodes[i] = doc.getDocumentElement();
               	        break;
                    case BINARY:	//not used
                		StringWriter sw = new StringWriter();
                		writeBase64BinaryAndOptionallyCalcMsgDigest(infiles[i], "\n", sw, false, null);
                    	sw.close();
    	    			nodes[i] = doc.createTextNode(sw.toString());
                    	break;
                    case TEXT:		//not used
                		StringBuffer sb = new StringBuffer();
                    	BufferedReader br = new BufferedReader(new FileReader(new File(infiles[i])));
                    	char[] buf = new char[UtilShared.defaultBufSize];
                    	while((len = br.read(buf)) != -1)
                    		sb.append(new String(buf, 0, len));
                    	br.close();
                    	br = null;
    	    			nodes[i] = doc.createTextNode(sb.toString());
                    	break;
                    }
            	}
            }
         
            XMLSignatureFactory xmlSigFactory;
            if (defaultSignatureFactoryProvider != null) 
    			xmlSigFactory = XMLSignatureFactory.getInstance("DOM", defaultSignatureFactoryProvider);
    		 else
    			xmlSigFactory = XMLSignatureFactory.getInstance();
    		if (sigDocType == SigDocType.XML) {
    			//use Inclusive for None
           		transforms = Collections.singletonList(xmlSigFactory.newTransform(getCanonicalizationMethod(sigXmlTransform), (TransformParameterSpec) null));
            } else if (sigDocType == SigDocType.BINARY) {
                //not used in this packaging
            	transforms = Collections.singletonList(xmlSigFactory.newTransform(CanonicalizationMethod.BASE64, (TransformParameterSpec) null));
            }
            KeyInfo keyInfo = null;
            String keyRefId = getSigRefUriVal();
            if (!isExcludeKeyInfoFromSignature) {
	            KeyInfoFactory keyInfoFactory = xmlSigFactory.getKeyInfoFactory();
	            if (sigPubCert != null) {
		            X509Data certdata = keyInfoFactory.newX509Data(Collections.singletonList(sigPubCert));
		            keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(certdata), keyRefId);
	            } else {
	            	PublicKey key = UtilShared.getPublicKey(sigkey);
	            	if (key != null) {
	            		KeyValue keyval = keyInfoFactory.newKeyValue(key);
	            		keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(keyval), keyRefId);
	            	}
	            }
            }
    		xmlobjs = new ArrayList<XMLObject>();
        	List<Reference> sigRefs = new ArrayList<Reference>();
            if (keyInfo != null && isSignKeyInfo) {
	            Reference keyRef = xmlSigFactory.newReference("#"+ keyRefId, xmlSigFactory.newDigestMethod(xmlTagDigestMethodAlgoValue, null),
	            		transforms, null, null);
	            sigRefs.add(keyRef);
            }
        	List<XMLStructure> contentList, sigPropList = getSignaturePropertyList(doc, sigDocType);
            Reference[] refs = new Reference[infiles.length];
    		for (int i = 0; i < infiles.length; i++) {
    			contentList = new ArrayList<XMLStructure>();
   				ri = sd.refInfos.get(i);
   				ri.refUriVal = getSigRefUriVal();
                refs[i] = xmlSigFactory.newReference("#" + ri.refUriVal, xmlSigFactory.newDigestMethod(xmlTagDigestMethodAlgoValue, null), transforms, null, null);
                sigRefs.add(refs[i]);
        		switch(sigRefIdPos) {
        		case Object:
           			if (sigPropList.size() > 0) {
               			sigProp = xmlSigFactory.newSignatureProperty(sigPropList, "#" + xmlTagSignatureIdValue, null);
               			sigProps = xmlSigFactory.newSignatureProperties(Collections.singletonList(sigProp), null);
               			contentList.add(sigProps);
           			}
       				contentList.add(new DOMStructure(nodes[i]));
           			xmlobj = xmlSigFactory.newXMLObject(contentList, ri.refUriVal, null, null);
           			xmlobjs.add(xmlobj);
                	break;
        		case SignatureProperty:
        			for (int j = 0; j < sigPropList.size(); j++)
    	    			contentList.add(sigPropList.get(j));
       				contentList.add(new DOMStructure(nodes[i]));
    				sigProp = xmlSigFactory.newSignatureProperty(contentList, "#" + xmlTagSignatureIdValue, ri.refUriVal);
        			sigProps = xmlSigFactory.newSignatureProperties(Collections.singletonList(sigProp), null);
        			xmlobj = xmlSigFactory.newXMLObject(Collections.singletonList(sigProps), null, null, null);
           			xmlobjs.add(xmlobj);
        			break;
        		case SignatureProperties:
        			for (int j = 0; j < sigPropList.size(); j++)
    	    			contentList.add(sigPropList.get(j));
       				contentList.add(new DOMStructure(nodes[i]));
    				sigProp = xmlSigFactory.newSignatureProperty(contentList, "#" + xmlTagSignatureIdValue, null);
        			sigProps = xmlSigFactory.newSignatureProperties(Collections.singletonList(sigProp), ri.refUriVal);
        			xmlobj = xmlSigFactory.newXMLObject(Collections.singletonList(sigProps), null, null, null);
           			xmlobjs.add(xmlobj);
        			break;
        		}
    		}
    		//DO NOT CHANGE CanonicalizationMethod.INCLUSIVE in SignedInfo
            SignedInfo signedInfo = xmlSigFactory.newSignedInfo(
            		xmlSigFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
            		xmlSigFactory.newSignatureMethod(xmlTagSignatureMethodAlgoValue, null), sigRefs);
            XMLSignature signature = xmlSigFactory.newXMLSignature(signedInfo, keyInfo, xmlobjs, xmlTagSignatureIdValue, null);
	        doc = docBuilder.newDocument();
            DOMSignContext dsc = new DOMSignContext(sigkey, doc);
            dsc.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
            if (signaturePrefix != null && !"".equals(signaturePrefix))
            	dsc.setDefaultNamespacePrefix(signaturePrefix);
           	signature.sign(dsc);
           	sd.doc = doc;
           	if (isBlankDoc) {
               	Element si = (Element)doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignedInfo").item(0);
        		for (int i = 0; i < infiles.length; i++) {
        			ri = sd.refInfos.get(i);
                   	ri.referenceElem = UtilShared.getElementWithASpecificAttribute(si, "URI", "#" + ri.refUriVal);
                   	Data data = xmlSigFactory.getURIDereferencer().dereference(refs[i], dsc);
                   	if (data instanceof NodeSetData) {
                   		NodeSetData nodeSetData = (NodeSetData)data;;
                   		if (nodeSetData.iterator().hasNext()) {
                   			Object obj = nodeSetData.iterator().next();
                   			if (obj instanceof Element)
                   				ri.referencedElem = (Element)obj;
                   		}
                   	}
        		}
           	}
    	} finally {
    		if (bis != null) try{bis.close();}catch(Throwable t){}
    	}
		logger.debug("<-- createSignedDOMDoc()");
    	return sd;
    }
	
	protected int writeEncodedBinary(int lastlinelen, byte[] buf, String newline, Writer writer) throws Exception {
		String encoded = Base64.encode(buf).replace("\r", "").replace("\n", "");
		int strlen = encoded.length();
		if (lastlinelen + strlen < 76) {
			writer.write(encoded);
			lastlinelen += strlen;
		} else {
			String tmpS = encoded.substring(0, 76 - lastlinelen);
			writer.write(tmpS);
			writer.write(newline);
			encoded = encoded.substring(tmpS.length());
			lastlinelen = 0;
			while (encoded.length() >= 76) {
				tmpS = encoded.substring(0, 76 - lastlinelen);
				writer.write(tmpS);
				writer.write(newline);
				encoded = encoded.substring(tmpS.length());
			}
			if (encoded.length() > 0) {
				writer.write(encoded);
				lastlinelen = encoded.length();
			}
		}
		return lastlinelen;
	}
	
	protected boolean writeTextFileObjectContent(String infile, Writer writer) throws Exception {
		logger.debug("--> writeTextFileObjectContent(). infile=" + infile);
    	boolean ret = false;
    	String tmp;
    	BufferedReader bis = null;
    	try {
	    	bis = new BufferedReader(new FileReader(new File(infile)));
	        int len;
	        char[] tmpBuf = new char[UtilShared.defaultBufSize];
	        while((len = bis.read(tmpBuf)) != -1) {
	        	//used for TEXT signing with no transformation so write exact content for which digest was calculated 
				tmp = new String(tmpBuf, 0, len);
				if (tmpBuf[len-1] == '\r') {
					len = bis.read();
					if (len != -1)
						tmp = tmp + (char)len;
				}
				//used while signing with no transformation - so write exactly the way digest was calculated
				tmp = tmp.replace("\r\n", "\n").replace("\r", "\n");
				tmp = tmp.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
				writer.write(tmp);
	        }
	        bis.close();
	        bis = null;
    	} finally {
    		if (bis != null) try{bis.close();}catch(Throwable t){}
    	}
		logger.debug("<-- writeTextFileObjectContent()");
    	return ret;
	}
	
	//JDK only supports DOM based signing api - so file size, to sign, is limited by heap. this method calculate digest by reading a file stream 
	//(do not need to load entire file as required in DOM) - once digest is calculated using right transformation, rest is easy - 
	//create blank signed document, then update <DigestValue> and <SignedInfo> which is then used to calculate signature value 
	//which is then populated in <SignatureValue>. eventually write enveloping signature and payload in output file  
    protected boolean signFileStreaming(String[] infiles, String outfile, PrivateKey sigkey, X509Certificate sigPubCert, 
    		SigDocType sigDocType, SigXmlTransform sigXmlTransform) throws Exception {
		logger.debug("--> signFileStreaming(). infiles=" + prettyNames(infiles) + ", outfile=" + outfile + ", sigDocType=" + sigDocType + ", sigXmlTransform=" + sigXmlTransform);
    	boolean ret = false;
        BufferedWriter bw = null;
        BufferedReader br = null;
        RandomAccessFile raf = null;
		File[] tmpBase64FilesToDelete = null;
		String[] tmpBase64Files = null;
		Node node;
		NodeList nodeList;
		Signature signature;
		byte[] buf; char[] cbuf;
		int len;
		ReferenceInfo ri = null;
		String[] arr = null;
		String tmpSignedXml = null;
    	try {
        	boolean isNSAware = true, isBlankDoc = true;
        	if (sigDocType == SigDocType.XML)
        		isNSAware = isXMLNameSpaceAware(infiles);
        	SignedDocument strmBlankDoc = createSignedDOMDoc(infiles, sigkey, sigPubCert, sigDocType, sigXmlTransform, isNSAware, isBlankDoc);
        	Document blankDoc = strmBlankDoc.doc;
        	if (sigDocType == SigDocType.XML) {
	    		tmpSignedXml = UtilShared.getTmpFileName(infiles[0], "signed.xml");
	    		bw = new BufferedWriter(new FileWriter(new File(tmpSignedXml)));
	    		bw.write(new XmlDeclaration().toXmlDeclStr());
	    		arr = strmBlankDoc.getXmlChunkBeforeAndAfterStrmSigFakeStr();
        	}
    		int curXmlChunkPos = 0;
    		for (int i = 0; i < strmBlankDoc.refInfos.size(); i++) {
    			ri = strmBlankDoc.refInfos.get(i);
        		switch(sigDocType) {
        		case XML:
            		bw.write(arr[curXmlChunkPos++]);
        	    	logger.debug("parsing xml...." + new Date());
        	    	calcCanonicalizedXmlMsgDigestByParsingDocChunk(bw, ri, sigXmlTransform);
    	    		logger.debug("parsing xml....done. " + new Date());
    				break;
        		case WRAPPEDXML:
    				calcXmlMsgDigestNoTransformation(ri);
    				break;
        		case TEXT:	//not used
        			calcTextMsgDigestNoTransformation(ri);
        			break;
        		case BINARY:	//not used
        			if (tmpBase64Files == null)
        				tmpBase64Files = new String[strmBlankDoc.refInfos.size()];
        			tmpBase64Files[i] = UtilShared.getTmpFileName(ri.infile, "base64");
        			bw = new BufferedWriter(new FileWriter(new File(tmpBase64Files[i])));
                    writeBase64BinaryAndOptionallyCalcMsgDigest(ri.infile, "\r\n", bw, true, ri.md);
                    bw.close(); 
                    bw = null;
        			break;
        		}
    		}
    		if (sigDocType == SigDocType.XML) {
    			bw.write(arr[curXmlChunkPos]);
    			bw.close();
    			bw = null;
    		}
            String signatureValue = null, digestValue = null;
    		for (int i = 0; i < strmBlankDoc.refInfos.size(); i++) {
    			ri = strmBlankDoc.refInfos.get(i);
        		nodeList = ri.referenceElem.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestValue");
                if (nodeList.getLength() > 0) {
                	node = nodeList.item(0);
                	node = node.getFirstChild();
                	digestValue = ri.digest();
                	logger.debug("DigestValue=" + digestValue);
                	node.setNodeValue(digestValue);
                } else
                	throw new Exception("Invalid document structure. Missing <DigestValue> content");
    		}
            nodeList = blankDoc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignedInfo");
            if (nodeList.getLength() > 0) {
            	node = nodeList.item(0);
            	byte[] signedInfoBuf = getInclusiveTransformedElemXml((Element)node).getBytes();
                if (defaultSignatureProvider != null)
                	signature = Signature.getInstance(SIGNATUER_ALGO, defaultSignatureProvider);
                else
                	signature = Signature.getInstance(SIGNATUER_ALGO);
                logger.debug("SignedInfo=" + new String(signedInfoBuf));
                signature.initSign(sigkey);
				signature.update(signedInfoBuf);
				buf = signature.sign();
    			signatureValue = Base64.encode(buf);
    			//logger.debug("SignatureValue=" + signatureValue);
                nodeList = blankDoc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
                if (nodeList.getLength() > 0)
                	nodeList.item(0).getFirstChild().setNodeValue(signatureValue);
                else
                	throw new Exception("Invalid document structure. Missing <SignatureValue> content");
            } else
            	throw new Exception("Invalid document structure. Missing <SignedInfo> content");
            if (sigDocType == SigDocType.XML) {
                //modify digestvalue and signaturevalue
                //read at least until SignatureValue> 
                raf = new RandomAccessFile(tmpSignedXml, "rw");
    			int startPos, endPos;
    			buf = new byte[1024];
    			byte[] readBuf = null, tmpBuf;
    			String tmps;
    			startPos = endPos = -1;
    			//<ds:SignatureValue>.......</ds:SignatureValue> or <SignatureValue>.......</SignatureValue>
    			while (startPos == -1 || endPos == -1) {
    				len = raf.read(buf);
    				if (len == -1)
    					break;
    				if (readBuf == null) {
    					readBuf = new byte[len];
    					System.arraycopy(buf, 0, readBuf, 0, len);
    				}
    				else {
    					tmpBuf = new byte[readBuf.length + len];
    					System.arraycopy(readBuf, 0, tmpBuf, 0, readBuf.length);
    					System.arraycopy(buf, 0, tmpBuf, readBuf.length, len);
    					readBuf = tmpBuf;
    				}
    				tmps = new String(readBuf);
    				if (startPos == -1)
    					startPos = tmps.indexOf("SignatureValue>");
    				if (startPos != -1)
    					endPos = tmps.indexOf("<", startPos);
    			}
    	        if (startPos == -1 || endPos == -1)
    	        	throw new Exception("bug. 'SignatureValue>' is missing in file=" + tmpSignedXml);
    	        tmps = new String(readBuf, 0, endPos);
    	        //modify blank doc xml SignatureValue with SignatureValue signed with calculated digest value 
    	        StringBuilder deststr = new StringBuilder();
    	        deststr.append(tmps.substring(0, startPos)); 
    	        deststr.append("SignatureValue>"); 
    	        deststr.append(signatureValue);
    	        //modify all DigestValue
    	        int pos = 0;
    	        String srcstr;
        		for (int i = 0; i < strmBlankDoc.refInfos.size(); i++) {
        			ri = strmBlankDoc.refInfos.get(i);
                	srcstr = deststr.toString();
        	        deststr = new StringBuilder();
        	        pos = srcstr.indexOf(ri.refUriVal);
        	        if (pos == -1)
        	        	throw new Exception("bug. " + ri.refUriVal + " is missing in file=" + tmpSignedXml);
        	        startPos = srcstr.indexOf("DigestValue>", pos);
        	        endPos = srcstr.indexOf("<", startPos);
        	        if (startPos == -1 || endPos == -1)
        	        	throw new Exception("bug. 'DigestValue>' is missing in file=" + tmpSignedXml);
        	        deststr.append(srcstr.substring(0, startPos));
        	        deststr.append("DigestValue>");
                	deststr.append(ri.digest());
                	deststr.append(srcstr.substring(endPos));
        		}
    	        if (tmps.length() != deststr.length()) {
    	        	logger.error("blank signed doc upto tmps len=" + tmps.length() + ", tmps=" + tmps);
    	        	logger.error("deststr after SignatureValue and DigestValue(s) modified len=" + deststr.length() + ", deststr=" + deststr);
    	        	throw new Exception("bug. either new SignaturValue or DigestValue length differs from their corresponding length in file=" + tmpSignedXml);
    	        }
    	        raf.seek(0);
    	        raf.write(deststr.toString().getBytes());
    	        raf.close(); raf = null;
    	        //rename tmpXmlFile to outfile
    	        File src = new File(tmpSignedXml), dest = new File(outfile);
    	        if (dest.exists())
    	        	dest.delete();
    	        if (!src.renameTo(dest))
    	        	throw new Exception("bug. unable to rename " + tmpSignedXml + " to " + outfile);
            } else { //of if (sigDocType == SigDocType.XML)
                bw = new BufferedWriter(new FileWriter(new File(outfile)));
			    bw.write(new XmlDeclaration().toXmlDeclStr());
                arr = strmBlankDoc.getXmlChunkBeforeAndAfterStrmSigFakeStr();
        		curXmlChunkPos = 0;
        		String file;
        		tmpBase64FilesToDelete = new File[strmBlankDoc.refInfos.size()];
                for (int i = 0; i < strmBlankDoc.refInfos.size(); i++) {
                	ri = strmBlankDoc.refInfos.get(i);
            		bw.write(arr[curXmlChunkPos++]);
            		file = ri.infile;
            		switch(sigDocType) {
            		case XML:
            			throw new Exception("bug. XML should not be processed here");
            		case BINARY:	//not used
            			tmpBase64FilesToDelete[i] = new File(tmpBase64Files[i]);
            			file = tmpBase64Files[i];
            			//do not break;
            		case WRAPPEDXML:
            			br = new BufferedReader(new FileReader(file));
            			cbuf = new char[UtilShared.defaultBufSize];
            			while ((len = br.read(cbuf)) != -1)
            				bw.write(cbuf, 0, len);
            			br.close();
            			br = null;
            			break;
            		case TEXT:	//not used
            			writeTextFileObjectContent(file, bw);
            			break;
            		}
                }
        		bw.write(arr[curXmlChunkPos]);
                bw.close(); 
                bw = null;
            }
        	ret = true;
    	} finally {
    		if (bw != null) try{bw.close();}catch(Throwable t){}
    		if (raf != null) try{raf.close();}catch(Throwable t){}
    		if (br != null) try{br.close();}catch(Throwable t){}
    		if (tmpBase64FilesToDelete != null) {
    			for (int i = 0; i < tmpBase64FilesToDelete.length; i++) {
    				if (tmpBase64FilesToDelete[i] != null && tmpBase64FilesToDelete[i].exists()) try{if(!tmpBase64FilesToDelete[i].delete())tmpBase64FilesToDelete[i].deleteOnExit();}catch(Throwable t){}
    			}
    		}
    	}
		if (isVerifyAllSignature && signatureVerifier != null)
			signatureVerifier.verifySignatureStreaming(outfile, sigPubCert.getPublicKey());
    	logger.debug("<-- signFileStreaming()");
    	return ret;
    }
    
    //to sign xml with no namespace. <name>Subir Paul</name> 
    protected boolean isXMLNameSpaceAware(String[] infiles) throws Exception {
    	boolean ret = true, flag;
		for (int i = 0; i < infiles.length; i++) {
			flag = isXMLNameSpaceAware(infiles[i]);
			if (i == 0)
				ret = flag;
			else if (ret != flag)
				throw new Exception("all files need to be either NS aware or not. " + infiles[i] + " NSawareness=" + flag
						+ " but " + infiles[i-1] + " NSawareness=" + ret);
		}
		return ret;
    }
    
    protected boolean isXMLNameSpaceAware(String infile) throws Exception {
		XMLStreamReader reader = null;
		FileInputStream fis = null;
		boolean ret = false;
		try {
    		boolean startElemFound = false;
			//do not use FileReader as reader breaks if xml starts with utf8 BOM, EFBBBF (editor such as notepad urf8 encoding uses BOM)
    		fis = new FileInputStream(new File(infile));
    		reader = XMLInputFactory.newFactory().createXMLStreamReader(fis);
    		while(!startElemFound && !ret && reader.hasNext()) {
    			switch(reader.getEventType()) {
    			case XMLStreamConstants.START_ELEMENT:
    				int nscount = reader.getNamespaceCount();
    				if (nscount != 0)
    					ret = true;
    				startElemFound = true;
    				break;
    			}
    			reader.next();
    		}
    		reader.close();
    		reader = null;
    		fis.close();
    		fis = null;
		}
		finally {
			if (reader != null) try{reader.close();}catch(Throwable t){}
			if (fis != null) try{fis.close();}catch(Throwable t){}
		}
		return ret;
    }
    
    //signs a file
    protected boolean signFile(String[] infiles, String outfile, PrivateKey sigkey, X509Certificate sigPubCert, 
    		SigDocType sigDocType, SigXmlTransform sigXmlTransform) throws Exception {
		logger.debug("--> signFile(). infiles=" + prettyNames(infiles) + ", outfile=" + outfile + ", sigDocType=" + sigDocType + ", sigXmlTransform=" + sigXmlTransform);
		BufferedWriter bw = null;
		boolean ret = false;
    	try {
    		//DOM based signing. Check if the XML root element has NS.
    		boolean isBlankDoc = false, isNSAware = true;
        	if (sigDocType == SigDocType.XML)
        		isNSAware = isXMLNameSpaceAware(infiles);
	    	SignedDocument signedDoc = createSignedDOMDoc(infiles, sigkey, sigPubCert, sigDocType, sigXmlTransform, isNSAware, isBlankDoc);
	    	NodeList nodeList = signedDoc.doc.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestValue");
	        if (nodeList.getLength() > 0)
	        	logger.debug("DigestValue=" + nodeList.item(0).getFirstChild().getNodeValue());
	    	bw = new BufferedWriter(new FileWriter(new File(outfile)));
	    	Transformer trans = TransformerFactory.newInstance().newTransformer();
            trans.transform(new DOMSource(signedDoc.doc), new StreamResult(bw));
            bw.close();
            bw = null;
	        ret = true;
		} finally {
			if (bw != null) try{bw.close();}catch(Throwable t){}
		}
   		if (isVerifyAllSignature && signatureVerifier != null)
    		signatureVerifier.verifySignature(outfile, sigPubCert.getPublicKey());
    	logger.debug("<-- signFile()");
    	return ret;
    }
    
    //create base64 encoded binary, wrap in xml and sign
    protected boolean wrapBinaryFileInXmlAndSign(String[] infiles, String outfile, PrivateKey sigkey, 
    		X509Certificate sigPubCert, boolean isDOM) throws Exception {
		logger.debug("--> wrapBinaryFileInXmlAndSign(). infiles=" + prettyNames(infiles) + ", outfile=" + outfile + ", isDOM=" + isDOM);
		boolean flag = false;
		String[] tags = getWrapperTags();
        BufferedWriter bw = null;
        try {
	        String[] wrappedBase64Files = new String[infiles.length];
	        for (int i = 0; i < infiles.length; i++) {
	        	wrappedBase64Files[i] = UtilShared.getTmpFileName(infiles[i], "wrapped.base64.xml");
	    		bw = new BufferedWriter(new FileWriter(new File(wrappedBase64Files[i])));
	    		bw.write(tags[0]);
	            writeBase64BinaryAndOptionallyCalcMsgDigest(infiles[i], "\r\n", bw, false, null);
	            bw.write(tags[1]);
	            bw.close();
	            bw = null;
	        }
	        if (isDOM)
	        	flag = signFile(wrappedBase64Files, outfile, sigkey, sigPubCert, SigDocType.WRAPPEDXML, SigXmlTransform.None);
	        else
	        	flag = signFileStreaming(wrappedBase64Files, outfile, sigkey, sigPubCert, SigDocType.WRAPPEDXML, SigXmlTransform.None);
	        File f[] = new File[wrappedBase64Files.length];
	        for (int i = 0; i < wrappedBase64Files.length; i++) {
	            f[i] = new File(wrappedBase64Files[i]);
	            if (f[i].exists() && !f[i].delete()) f[i].deleteOnExit();
	        }
		} finally {
			if (bw != null) try{bw.close();}catch(Throwable t){}
        }
		logger.debug("<-- wrapBinaryFileInXmlAndSign()");
		return flag;
    }

    //wrap text xml and sign
    protected boolean wrapTextFileInXmlAndSign(String[] infiles, String outfile, PrivateKey sigkey, 
    		X509Certificate sigPubCert, boolean isDOM) throws Exception {
		logger.debug("--> wrapTextFileInXmlAndSign(). infiles=" + prettyNames(infiles) + ", outfile=" + outfile + ", isDOM=" + isDOM);
		boolean flag = false;
    	int len;
        char[] tmpBuf = new char[UtilShared.defaultBufSize];
		String[] tags = getWrapperTags();
        BufferedWriter bw = null;
		BufferedReader br = null;
		String tmpS;
		try {
	        String[] wrappedTextFiles = new String[infiles.length];
	        for (int i = 0; i < infiles.length; i++) {
	        	wrappedTextFiles[i] = UtilShared.getTmpFileName(infiles[i], "wrapped.txt.xml");
	    		br = new BufferedReader(new FileReader(new File(infiles[i])));
	    		bw = new BufferedWriter(new FileWriter(new File(wrappedTextFiles[i])));
	    		bw.write(tags[0]);
	            while((len = br.read(tmpBuf)) != -1) {
	            	tmpS = new String(tmpBuf, 0, len);
					if (tmpBuf[len-1] == '\r') {
						len = br.read();
						if (len != -1)
							tmpS = tmpS + (char)len;
					}
					//process end of line per xml spec; replace \r\n with \n and all \r (which do not followed by \n) with \n
					tmpS = tmpS.replace("\r\n", "\n").replace("\r", "\n");
					//wrapped in xml; so <>& not allowed
	            	tmpS = tmpS.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
	    			bw.write(tmpS);
	            }
	            br.close();
	            br = null;
	            bw.write(tags[1]);
	            bw.close();
	            bw = null;
	        }
	        if (isDOM)
	        	flag = signFile(wrappedTextFiles, outfile, sigkey, sigPubCert, SigDocType.WRAPPEDXML, SigXmlTransform.None);
	        else
	        	flag = signFileStreaming(wrappedTextFiles, outfile, sigkey, sigPubCert, SigDocType.WRAPPEDXML, SigXmlTransform.None);
	        File f[] = new File[wrappedTextFiles.length];
	        for (int i = 0; i < wrappedTextFiles.length; i++) {
	            f[i] = new File(wrappedTextFiles[i]);
	            if (f[i].exists() && !f[i].delete()) f[i].deleteOnExit();
	        }
		} finally {
			if (br != null) try{br.close();}catch(Throwable t){}
			if (bw != null) try{bw.close();}catch(Throwable t){}
        }
		logger.debug("<-- wrapTextFileInXmlAndSign()");
		return flag;
    }

    protected boolean signFileNoWrap(String[] infiles, String outfile, PrivateKey sigkey, X509Certificate sugPubCert, 
    		boolean isDom, SigDocType sigDocType) throws Exception {
    	return signFileNoWrap(infiles, outfile, sigkey, sugPubCert, isDom, sigDocType, sigXmlTransform);
    }
    
    protected boolean signFileNoWrap(String[] infiles, String outfile, PrivateKey sigkey, X509Certificate sugPubCert, 
    		boolean isDom, SigDocType sigDocType, SigXmlTransform sigXmlTransform) throws Exception {
		logger.debug("--> signFileNoWrap(). infiles=" + prettyNames(infiles) + ", outfile=" + outfile + ", isDom=" + isDom + ", sigDocType=" + sigDocType + ", sigXmlTransform=" + sigXmlTransform);
    	boolean flag = false;
    	if (isDom)
    		flag = signFile(infiles, outfile, sigkey, sugPubCert, sigDocType, sigXmlTransform);
    	else
    		flag = signFileStreaming(infiles, outfile, sigkey, sugPubCert, sigDocType, sigXmlTransform);
    	logger.debug("<-- signFileNoWrap()");
		return flag;
    }
    
	//<Reference URI="#ObjRefId">, <Object Id="ObjRefId">
    protected String getSigRefUriVal() {
    	if (isGenRandomRefUri)
    		return "RefId-" + Base64.encode(UtilShared.genUniqueRandomId().getBytes()).replace("\r", "").replace("\n", "")
    				.replace("+", "").replace("/", "").replace("=", "");
    	return "RefId-" + refUriGenId.getAndIncrement();
    }
    
    //sign a xml file - streaming based
    public boolean signXmlFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = false;
        String[] infiles = UtilShared.getFiles(infile);
    	return signFileNoWrap(infiles, outfile, sigkey, sugPubCert, isDom, SigDocType.XML, sigXmlTransform);
    }

    public boolean wrapBinaryFileInXmlAndSignStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = false;
        String[] infiles = UtilShared.getFiles(infile);
    	return wrapBinaryFileInXmlAndSign(infiles, outfile, sigkey, sugPubCert, isDom);
    }

    public boolean wrapTextFileInXmlAndSignStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = false;
        String[] infiles = UtilShared.getFiles(infile);
    	return wrapTextFileInXmlAndSign(infiles, outfile, sigkey, sugPubCert, isDom);
    }

    //sign a xml file - dom based
    public boolean signXmlFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = true;
        String[] infiles = UtilShared.getFiles(infile);
    	return signFileNoWrap(infiles, outfile, sigkey, sugPubCert, isDom, SigDocType.XML);
    }
    
    //wrap text in xml and sign - dom based
    public boolean wrapTextFileInXmlAndSign(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = true;
    	String[] infiles = UtilShared.getFiles(infile);
    	return wrapTextFileInXmlAndSign(infiles, outfile, sigkey, sugPubCert, isDom);
    }

    //create baed64 encoded binary, wrap in xml and sign - dom based
    public boolean wrapBinaryFileInXmlAndSign(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = true;
    	String[] infiles = UtilShared.getFiles(infile);
    	return wrapBinaryFileInXmlAndSign(infiles, outfile, sigkey, sugPubCert, isDom);
    }

    //not used in this packaging
    public boolean signTextFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	String[] infiles = UtilShared.getFiles(infile);
    	return signFileNoWrap(infiles, outfile, sigkey, sugPubCert, true, SigDocType.TEXT, SigXmlTransform.None);
    }

    //not used in this packaging
    public boolean signBinaryFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	String[] infiles = UtilShared.getFiles(infile);
    	return signFileNoWrap(infiles, outfile, sigkey, sugPubCert, true, SigDocType.BINARY, SigXmlTransform.None);
    }
    
    //not used in this packaging
    public boolean signTextFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = false;
    	String[] infiles = UtilShared.getFiles(infile);
    	return signFileNoWrap(infiles, outfile, sigkey, sugPubCert, isDom, SigDocType.TEXT, SigXmlTransform.None);
    }

    //not used in this packaging
    public boolean signBinaryFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception {
    	boolean isDom = false;
    	String[] infiles = UtilShared.getFiles(infile);
    	return signFileNoWrap(infiles, outfile, sigkey, sugPubCert, isDom, SigDocType.BINARY, SigXmlTransform.None);
    }

    public ISignatureVerifier getSignatureVerifier() {
    	return signatureVerifier;
    }
    
	public void setSignatureVerifier(ISignatureVerifier val) {
		signatureVerifier = val;
	}

	public Object getProperty(String prop) {
		if ("isExcludeKeyInfoFromSignature".equalsIgnoreCase(prop))
			return isExcludeKeyInfoFromSignature;
		if ("isWrapperXsi".equalsIgnoreCase(prop))
			return useWrapperXsi;
		if ("isWrapperXsiSchemaLoc".equalsIgnoreCase(prop))
			return useWrapperXsiSchemaLoc;
		if ("getSignaturePrefix".equalsIgnoreCase(prop))
			return signaturePrefix;
		if ("getSigRefIdPos".equalsIgnoreCase(prop))
			return sigRefIdPos;
		if ("getSigXmlTransform".equalsIgnoreCase(prop))
			return sigXmlTransform;
		if ("getWrapperNS".equalsIgnoreCase(prop))
			return wrapperNS;
		if ("getWrapperPrefix".equalsIgnoreCase(prop))
			return wrapperPrefix;
		if ("getWrapperXsi".equalsIgnoreCase(prop))
			return wrapperXsi;
		if ("getWrapperXsiSchemaLoc".equalsIgnoreCase(prop))
			return wrapperXsiSchemaLoc;
		if ("getDebugBuf".equalsIgnoreCase(prop) || "getSigningDebugBuf".equalsIgnoreCase(prop))
			return digestBuf;
		if ("isAddSignaturePropTimestamp".equalsIgnoreCase(prop))
			return isAddSignaturePropTimestamp;
		return null;
	}
	
    public void setProperty(String prop, Object value) {
    	if ("setExcludeKeyInfoFromSignature".equalsIgnoreCase(prop) || "excludeKeyInfoFromSignature".equalsIgnoreCase(prop))
    		isExcludeKeyInfoFromSignature = (Boolean)value;
		//No prefix - <Signature xmlns="http://www.w3.org/2000/09/xmldsig#" ...>
		//With prefix 'dsig' - <dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" ...> 
	   else if ("setSignaturePrefix".equalsIgnoreCase(prop) || "signaturePrefix".equalsIgnoreCase(prop))
		   signaturePrefix = value.toString();
		else if ("setSigRefIdPos".equalsIgnoreCase(prop) || "sigRefIdPos".equalsIgnoreCase(prop))
			sigRefIdPos = SigRefIdPos.valueOf((String)value);
		else if ("setSigXmlTransform".equalsIgnoreCase(prop) || "sigXmlTransform".equalsIgnoreCase(prop))
			sigXmlTransform = SigXmlTransform.valueOf((String)value);
		//for wrapped text and/or binary signing
	    //<Wrapper xmlns="urn:xmpp:xml-element" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:xmpp:xml-element FileWrapper-1.1.xsd">
		else if ("setWrapperNS".equalsIgnoreCase(prop) || "wrapperNS".equalsIgnoreCase(prop))
			wrapperNS = value == null ? "" : value.toString();		
		else if ("setWrapperPrefix".equalsIgnoreCase(prop) || "wrapperPrefix".equalsIgnoreCase(prop))
			wrapperPrefix = value == null ? "" : value.toString();		
	    //xsi:schemaLocation="urn:xmpp:xml-element FileWrapper-1.1.xsd 
		else if ("setWrapperXsiSchemaLoc".equalsIgnoreCase(prop) || "wrapperXsiSchemaLoc".equalsIgnoreCase(prop))
			wrapperXsiSchemaLoc = "xsi:schemaLocation=\"" + value + "\"";
		else if ("isWrapperXsi".equalsIgnoreCase(prop))
			useWrapperXsi = (Boolean)value;
		else if ("isWrapperXsiSchemaLoc".equalsIgnoreCase(prop))
			useWrapperXsiSchemaLoc = (Boolean)value;
		else if ("setDebugBuf".equalsIgnoreCase(prop) || "setSigningDebugBuf".equalsIgnoreCase(prop))
			digestBuf = new byte[0];
		else if ("verifyAllSignature".equalsIgnoreCase(prop))
			isVerifyAllSignature = true;
		else if ("setDefaultSignatureFactoryProvider".equalsIgnoreCase(prop) && value instanceof Provider)
			defaultSignatureFactoryProvider = (Provider)value;
		else if ("isAddSignaturePropTimestamp".equalsIgnoreCase(prop))
			isAddSignaturePropTimestamp = (Boolean)value;
	}
}
