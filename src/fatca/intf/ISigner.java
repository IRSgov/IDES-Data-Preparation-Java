package fatca.intf;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/*
 * @author	Subir Paul (IT:ES:SE:PE)
 * 
 */
public interface ISigner extends ISignerNonXml, ISignerExtra {
	//FATCA uses Enveloping signature - meaning payload is enclosed within 'Signature' element

	//DOM based signing. DOM reads the entire xml in memory and thus xml file size is limited by heap size. 
	//JDK supports DOM based XML signing 
    public boolean signXmlFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
    
    //'SignatureValue' and 'MessageDigest' value using appropriate 'Transform' is dynamically done by reading XML file usinf streaming 
    //based XML parsing api. As it does not depends on JDK DOM based XML signature which requires entire XML file to be read into memory 
    //for signature, streaming based API can be used to sign very large XML file.
    public boolean signXmlFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sigPubCert) throws Exception;

    //Enveloping Signature XML tag to enclose payload. Valid values are Object|SignatureProperty|SignatureProperties
	public String getSigRefIdPos();
    public void setSigRefIdPos(String sigRefIdPos) throws Exception;
	
	//XML transformation used to sign payload (essentially calculating MessageDigest of payload before signature)
    //Valid values are Inclusive|InclusiveWithComments|Exclusive|ExclusiveWithComments|None
	public String getSigXmlTransform();
    public void setSigXmlTransform(String sigXmlTransform) throws Exception;
}
