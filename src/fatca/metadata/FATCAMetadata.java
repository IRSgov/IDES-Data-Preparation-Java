package fatca.metadata;

import intf.IMetadata;

import java.io.File;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.log4j.Logger;

import fatca.senderfilemetadata.BinaryEncodingSchemeCdType;
import fatca.senderfilemetadata.FATCAEntCommunicationTypeCdType;
import fatca.senderfilemetadata.FATCAIDESSenderFileMetadataType;
import fatca.senderfilemetadata.FileFormatCdType;
import fatca.senderfilemetadata.ObjectFactory;

import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl;

import util.UtilShared;

/*
 * @author	Subir Paul (OS:IT:ES:EST:PA:S1)
 * 
 */
public class FATCAMetadata implements IMetadata {
	protected static Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

	protected String emailAddress=null, origTranId = null; 
	protected int fileRevisionInd = -1;

	protected ObjectFactory objFMetadata = new ObjectFactory();
	protected SimpleDateFormat sdfFileCreateTs = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
	protected JAXBContext jaxbCtxMetadata;
	
	public FATCAMetadata() {
		try {
			jaxbCtxMetadata = JAXBContext.newInstance("fatca.senderfilemetadata");
		} catch(Throwable t) {
			t.printStackTrace();
			throw new RuntimeException(t);
		}
	}

	public void setMetadataInfo(String emailAddress, String fileRevisionId, String origTranId) {
		if (origTranId != null) {
			if ("null".equalsIgnoreCase(origTranId))
				this.origTranId = null;
			else
				this.origTranId = origTranId;
		}
		if (emailAddress != null) {
			if ("null".equalsIgnoreCase(emailAddress))
				this.emailAddress = null;
			else
				this.emailAddress = emailAddress;
		}
		if (fileRevisionId != null) {
			if ("true".equalsIgnoreCase(fileRevisionId))
				this.fileRevisionInd = 1;
			else if ("false".equalsIgnoreCase(fileRevisionId))
				this.fileRevisionInd = 0;
		}
	}

	//creates JAXB formatted tax year 
	protected XMLGregorianCalendar genTaxYear(int year) {
		XMLGregorianCalendar taxyear = new XMLGregorianCalendarImpl(new GregorianCalendar());
		taxyear.setTimezone(DatatypeConstants.FIELD_UNDEFINED);
		taxyear.setTime(DatatypeConstants.FIELD_UNDEFINED, DatatypeConstants.FIELD_UNDEFINED, DatatypeConstants.FIELD_UNDEFINED);
		taxyear.setDay(DatatypeConstants.FIELD_UNDEFINED);
		taxyear.setMonth(DatatypeConstants.FIELD_UNDEFINED);
		taxyear.setYear(year);
		return taxyear;
	}
	
	/*
<xsd:element ref="FATCAEntitySenderId"/>
<xsd:element ref="FATCAEntityReceiverId"/>
<xsd:element ref="FATCAEntCommunicationTypeCd"/>
<xsd:element ref="SenderFileId"/>
<xsd:element ref="FileCreateTs"/>
<xsd:element ref="TaxYear"/>
<xsd:element ref="FileRevisionInd"/>
<xsd:element ref="FileFormatCd" minOccurs="0"/>
<xsd:element ref="BinaryEncodingSchemeCd" minOccurs="0"/>
<xsd:element ref="OriginalIDESTransmissionId" minOccurs="0"/>
<xsd:element ref="SenderContactEmailAddressTxt" minOccurs="0"/>
	 */
	public String createMetadata(String folder, String senderGiin, String receiverGiin, String commType, 
			String senderFileId, String fileFormat, String binaryEncoding, Date fileCreateTs, int taxyear) throws Exception {
		logger.debug("--> createMetadata(). senderGiin=" + senderGiin + ", receiverGiin=" + receiverGiin + ", taxyear=" + taxyear + 
				", senderFileId=" + senderFileId + ", fileCreateTs=" + fileCreateTs + ", fileFormat=" + fileFormat + 
				", binaryEncoding=" + binaryEncoding + ", commType=" + commType);
		String metadatafile = UtilShared.getTmpFileName(folder, senderGiin, "Metadata.xml");
		JAXBContext jaxbCtxMetadata = JAXBContext.newInstance(FATCAIDESSenderFileMetadataType.class);            
		Marshaller mrshler = jaxbCtxMetadata.createMarshaller();
		mrshler.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
		FATCAIDESSenderFileMetadataType metadata = objFMetadata.createFATCAIDESSenderFileMetadataType();
		
		BinaryEncodingSchemeCdType binaryEncodingCd = binaryEncoding == null ? BinaryEncodingSchemeCdType.NONE : BinaryEncodingSchemeCdType.fromValue(binaryEncoding);
		FileFormatCdType fileFormatCd = fileFormat == null ? FileFormatCdType.XML : FileFormatCdType.fromValue(fileFormat);
		FATCAEntCommunicationTypeCdType commTypeCd = commType == null ? FATCAEntCommunicationTypeCdType.RPT : FATCAEntCommunicationTypeCdType.fromValue(commType);
		
		JAXBElement<FATCAIDESSenderFileMetadataType> jaxbElemMetadata = objFMetadata.createFATCAIDESSenderFileMetadata(metadata);
		metadata.setFATCAEntCommunicationTypeCd(commTypeCd);
		metadata.setFATCAEntitySenderId(senderGiin);
		if (fileRevisionInd == 1)
			metadata.setFileRevisionInd(true);
		else if (fileRevisionInd == 0)
			metadata.setFileRevisionInd(false);
		metadata.setSenderFileId(senderFileId);
		metadata.setTaxYear(genTaxYear(taxyear));
		metadata.setFATCAEntityReceiverId(receiverGiin);
		metadata.setFileCreateTs(sdfFileCreateTs.format(fileCreateTs));
		if (emailAddress != null)
			metadata.setSenderContactEmailAddressTxt(emailAddress);
		metadata.setBinaryEncodingSchemeCd(binaryEncodingCd);
		metadata.setFileFormatCd(fileFormatCd);
		if (origTranId != null)
			metadata.setOriginalIDESTransmissionId(origTranId);
		FileWriter fw = new FileWriter(new File(metadatafile));
		mrshler.marshal(jaxbElemMetadata, fw);
		fw.close();
		//mrshler.marshal(jaxbElemMetadata, System.out);
		logger.debug("<-- createMetadata()");
		return metadatafile;
	}
	
	public HashMap<String, String> getMetadataInfo(String metadataFile) throws Exception {
		HashMap<String, String>  map = new HashMap<String, String>();
		FATCAIDESSenderFileMetadataType md = (FATCAIDESSenderFileMetadataType)unmarshal(metadataFile);
		map.put("FATCAEntitySenderId", md.getFATCAEntitySenderId());
		map.put("FATCAEntityReceiverId", md.getFATCAEntityReceiverId());
		map.put("FATCAEntCommunicationTypeCd", md.getFATCAEntCommunicationTypeCd().value());
		map.put("SenderFileId", md.getSenderFileId());
		if (md.getFileFormatCd() != null)
			map.put("FileFormatCd", md.getFileFormatCd().value());
		if (md.getBinaryEncodingSchemeCd() != null)
			map.put("BinaryEncodingSchemeCd", md.getBinaryEncodingSchemeCd().value());
		map.put("FileCreateTs", md.getFileCreateTs());
		map.put("TaxYear", "" + md.getTaxYear());
		map.put("FileRevisionInd", "" + md.isFileRevisionInd());
		if (md.getOriginalIDESTransmissionId() != null)
			map.put("OriginalIDESTransmissionId", md.getOriginalIDESTransmissionId());
		if (md.getSenderContactEmailAddressTxt() != null)
			map.put("SenderContactEmailAddressTxt", md.getSenderContactEmailAddressTxt());
		return map;
	}
	
	public String getSenderId(HashMap<String, String> map) {
		return map.get("FATCAEntitySenderId");
	}
	
	public String getReceiverId(HashMap<String, String> map) {
		return map.get("FATCAEntityReceiverId");
	}
	
	public String getCommTypeCd(HashMap<String, String> map) {
		return map.get("FATCAEntCommunicationTypeCd");
	}
	
	public Object unmarshal(String metadataFile) throws Exception {
		Unmarshaller unmrshlr = null;
		Object obj = null;
		FATCAIDESSenderFileMetadataType metadataObj = null;
		//unmarshall metadata xml file content into Java bean/object
		unmrshlr = jaxbCtxMetadata.createUnmarshaller();
		obj = unmrshlr.unmarshal(new File(metadataFile));;
		if (obj instanceof JAXBElement<?>) {
			@SuppressWarnings("unchecked")
			JAXBElement<FATCAIDESSenderFileMetadataType> jaxbElem = (JAXBElement<FATCAIDESSenderFileMetadataType>)obj;
			metadataObj = jaxbElem.getValue();
		}
		return metadataObj;
	}
}
