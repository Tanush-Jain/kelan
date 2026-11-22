import xml.etree.ElementTree as ET


def parse_xml_payload(xml_content):
    # Insecure XXE sink parsing untrusted XML without defusedxml
    root = ET.fromstring(xml_content)
    return root.tag
