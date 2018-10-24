package intf;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/*
 * @author	Subir Paul (OS:IT:ES:EST:PA:S1)
 * 
 */
public interface ISigner extends ISignerNonXml {
	//this tool uses Enveloping signature - meaning payload is enclosed within 'Signature' element

	//DOM based signing. DOM reads the entire xml in memory and thus xml file size is limited by heap size. 
	//JDK supports DOM based XML signing 
    public boolean signXmlFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
    
    //'SignatureValue' and 'MessageDigest' value using appropriate 'Transform' is dynamically done by reading XML file using streaming 
    //based XML parsing api. As it does not depends on JDK DOM based XML signature which requires entire XML file to be read into memory 
    //for signature, streaming based API can be used to sign very large XML file.
    public boolean signXmlFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sigPubCert) throws Exception;

	/*
	 * excludeKeyInfoFromSignature=<true|false - default false>
	 * setBufSize=<value - default is 16K>
	 * setSignaturePrefix=<prefix - default no prefix>
	 * setSigRefIdPos=<Object|SignatureProperty|SignatureProperties - default Object>
	 * setSigXmlTransform=<Inclusive|InclusiveWithComments|Exclusive|ExclusiveWithComments - default Inclusive. Inclusive has been tested most>
	 * //for wrapped text and/or binary signing
	 * //<Wrapper xmlns="urn:xmpp:xml-element" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:xmpp:xml-element FileWrapper-1.1.xsd">
	 * wrapperNS=<wrapper ns - default "urn:xmpp:xml-element">
	 * wrappwrPrefix=<prefix - default none>
	 * wrapperXsiSchemaLoc=<schema loc - default "xsi:schemaLocation=\"urn:xmpp:xml-element FileWrapper-1.1.xsd\"">
	 * xmlChunkStreamingSize=<chunk size - default 32K>
	 * isWrapperXsi=<true|false - default false>
	 * isWrapperXsiSchemaLoc=<true|false - default false>
	 * verifyAllSignature=<true|false - default false. this valid
	 */
    public void setProperty(String prop, Object value);

	/*
	 * isExcludeKeyInfoFromSignature
	 * isWrapperXsi
	 * isWrapperXsiSchemaLoc
	 * getBufSize
	 * getSignaturePrefix
	 * getSigRefIdPos
	 * getSigXmlTransform
	 * getWrapperNS
	 * getWrapperPrefix
	 * getWrapperXsi
	 * getWrapperXsiSchemaLoc
	 * getXmlChunkStreamingSize
	 * getDebugBuf
	 */
    public Object getProperty(String prop);

    public ISignatureVerifier getSignatureVerifier();
	public void setSignatureVerifier(ISignatureVerifier val);
}
