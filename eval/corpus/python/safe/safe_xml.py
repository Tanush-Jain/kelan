import defusedxml.minidom


def safe_parse_xml(xml_content):
    dom = defusedxml.minidom.parseString(xml_content)
    return dom.documentElement.tagName
