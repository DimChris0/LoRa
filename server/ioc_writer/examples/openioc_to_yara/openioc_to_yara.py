# openioc_to_yara.py
#
# Copyright 2013 Mandiant Corporation.
# Licensed under the Apache 2.0 license.  Developed for Mandiant by William
# Gibb.
#
# Mandiant licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.
#
# Converts YARA signatures embedded into OpenIOC objects into a .yara file.
# See README for more information.
#
import argparse
import logging
import os
import sys
import ioc_writer.managers as managers
import ioc_writer.utils as utils

log = logging.getLogger(__name__)


class YaraConversionError(Exception):
    """
    Exception raised when processing an OpenIOC document into Yara.
    """
    pass


class YaraIOCManager(managers.IOCManager):
    def __init__(self):
        managers.IOCManager.__init__(self)
        self.register_parser_callback(self.yara_parse)
        self.ioc_names_set = set([])  # allows for quickly checking if a ioc name is present
        self.ioc_names_mangled_set = set([])  # set containing mangled names
        self.yara_signatures = {}  # guid -> yara string mapping

        self.metadata_fields = ['short_description', 'description', 'keywords', 'authored_by', 'authored_date']
        self.condition_to_yara_map = {'is': '==',
                                      'contains': '==',
                                      'greater-than': '>',
                                      'less-than': '<',
                                      'starts-with': None,
                                      'ends-with': None,
                                      'matches': None, }
        self.yara_II_condition_template = '%(prefix)s%(identifier)s %(condition)s%(postfix)s'
        self.yara_II_template = '%(prefix)s%(identifier)s '
        self.yara_set_string_template = '%(set_count)s of (%(set_ids)s)'
        self.yara_string_map = {'Yara/HexString': '$%(string_id)s = { %(content)s }',
                                'Yara/TextString': '$%(string_id)s = "%(content)s" %(modifiers)s',
                                'Yara/RegexString': '$%(string_id)s = /%(content)s/ %(modifiers)s',
                                'FileItem/Md5sum': '$%(string_id)s = %(content)s %(modifiers)s',
                                'FileItem/FileName': '$%(string_id)s = %(content)s %(modifiers)s',
                                'PortItem/remoteIP': '$%(string_id)s = %(content)s %(modifiers)s',
                                'DnsEntryItem/Host': '$%(string_id)s = %(content)s %(modifiers)s',
                                'DnsEntryItem/RecordName': '$%(string_id)s = %(content)s %(modifiers)s',
                                'Network/URI': '$%(string_id)s = %(content)s %(modifiers)s',
                                'RegistryItem/ValueName': '$%(string_id)s = %(content)s %(modifiers)s',
                                'RegistryItem/Text': '$%(string_id)s = %(content)s %(modifiers)s',
                                'ProcessItem/HandleList/Handle/Name': '$%(string_id)s = %(content)s %(modifiers)s',
                                'ProcessItem/name': '$%(string_id)s = %(content)s %(modifiers)s',
                                'FileItem/Sha1sum': '$%(string_id)s = %(content)s %(modifiers)s',
                                'FileItem/Sha256sum': '$%(string_id)s = %(content)s %(modifiers)s',
                                'RegistryItem/Path': '$%(string_id)s = %(content)s %(modifiers)s',
                                'FileItem/SizeInBytes': '$%(string_id)s = %(content)s %(modifiers)s',
                                'FileItem/PEInfo/PETimeStamp': '$%(string_id)s = %(content)s %(modifiers)s',
                                'FileItem/FullPath': '$%(string_id)s = /%(content)s/ %(modifiers)s',
                                'FileItem/PEInfo/DigitalSignature/CertificateSubject': '$%(string_id)s = %(content)s %(modifiers)s',
                                'ProcessItem/SectionList/MemorySection/Name': '$%(string_id)s = %(content)s %(modifiers)s',
                                'FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Name': '$%(string_id)s = %(content)s %(modifiers)s',
                                'RegistryItem/KeyPath': '$%(string_id)s = %(content)s %(modifiers)s',
                                'ProcessItem/arguments': '$%(string_id)s = %(content)s %(modifiers)s',
                                'FileItem/PEInfo/VersionInfoList/VersionInfoItem/OriginalFilename': '$%(string_id)s = %(content)s %(modifiers)s',
                                'FileItem/PEInfo/ImportedModules/Module/Name': '$%(string_id)s = %(content)s %(modifiers)s',
                                'Network/DNS': '$%(string_id)s = %(content)s %(modifiers)s',
                                'Snort/Snort': '$%(string_id)s = %(content)s %(modifiers)s',
                                'ProcessItem/SectionList/MemorySection/PEInfo/Exports/DllName': '$%(string_id)s = %(content)s %(modifiers)s',
                                'FileItem/PEInfo/Exports/NumberOfFunctions': '$%(string_id)s = %(content)s %(modifiers)s',
                                'FileItem/PEInfo/Exports/ExportedFunctions/string': '$%(string_id)s = %(content)s %(modifiers)s',
                                'FileItem/PEInfo/VersionInfoList/VersionInfoItem/FileDescription': '$%(string_id)s = %(content)s %(modifiers)s',
                                'FileItem/StringList/string': '$%(string_id)s = %(content)s %(modifiers)s',
                                'TaskItem/ActionList/Action/ExecProgramPath': '$%(string_id)s = %(content)s %(modifiers)s',
                                'TaskItem/TriggerList/Trigger/TriggerFrequency': '$%(string_id)s = %(content)s %(modifiers)s',
                                'TaskItem/AccountName': '$%(string_id)s = %(content)s %(modifiers)s'}

        self.yara_string_modifier_map = {'yara/wide': 'wide',
                                         'yara/ascii': 'ascii',
                                         'yara/fullword': 'fullword', }
        self.YARA_TEMPLATE = '''rule %(rule_name)s
{
    %(meta)s
    %(strings)s
    %(condition)s
}
'''
        self.YARA_TEMPLATE_NOSTRINGS = '''rule %(rule_name)s
{
    %(meta)s
    %(condition)s
}
'''
        self.YARA_META_TEMPLATE = '''meta:
%(meta)s'''
        self.YARA_STRINGS_TEMPLATE = '''strings:
%(strings)s'''
        self.YARA_CONDITION_TEMPLATE = '''condition:
        %(condition)s'''

    def yara_parse(self, ioc_obj):
        self.ioc_names_set.add(self.ioc_name[ioc_obj.iocid])
        self.ioc_names_mangled_set.add(mangle_name(self.ioc_name[ioc_obj.iocid]))

    def emit_yara(self):
        if len(self) < 1:
            log.error('No IOCs to convert')
        for iocid in self.iocs:
            name = self.ioc_name[iocid]
            name = mangle_name(name)
            # extract yara signatures in parts
            try:
                metadata_string = self.get_yara_metadata(iocid)
                strings_list = self.get_yara_stringlist(iocid)
                condition_string = self.get_yara_condition(iocid)
            except YaraConversionError:
                log.exception('Failed to parse [{}}]'.format(iocid))
                continue
            # extract an entire yara signatures embedded in Yara/Yara nodes
            embedded_signatures = self.get_embedded_yara(iocid)
            if embedded_signatures:
                log.debug('Additional embedded signatures found in [%s]' % iocid)
            yara_signature = ''
            if (not condition_string) and (not embedded_signatures):
                continue
            elif condition_string:
                mapping = {'rule_name': name,
                           'meta': self.YARA_META_TEMPLATE % {'meta': metadata_string},
                           'strings': self.YARA_STRINGS_TEMPLATE % {'strings': strings_list},
                           'condition': self.YARA_CONDITION_TEMPLATE % {'condition': condition_string}}

                if strings_list:
                    yara_signature = self.YARA_TEMPLATE % mapping
                else:
                    yara_signature = self.YARA_TEMPLATE_NOSTRINGS % mapping
            yara_signature += embedded_signatures
            self.yara_signatures[iocid] = yara_signature
        return True

    def get_embedded_yara(self, iocid):
        """
        Extract YARA signatures embedded in Yara/Yara indicatorItem nodes.
        This is done regardless of logic structure in the OpenIOC.
        """
        ioc_obj = self.iocs[iocid]
        ids_to_process = set([])
        signatures = ''
        for elem in ioc_obj.top_level_indicator.xpath('.//IndicatorItem[Context/@search = "Yara/Yara"]'):
            signature = elem.findtext('Content')
            signatures = signatures + '\n' + signature
        if signatures:
            signatures += '\n'
        return signatures

    def get_yara_condition(self, iocid):
        ioc_obj = self.iocs[iocid]
        ids_to_process = set([])
        tlo_id = ioc_obj.top_level_indicator.get('id')
        # './/IndicatorItem[Context/@document = "Yara" and Context/@search != "Yara/Yara"]'
        for elem in ioc_obj.top_level_indicator.xpath(
                './/IndicatorItem[Context/@search != "Yara/Yara"]'):
            current = elem
            elem_id = current.get('id')
            if elem_id in ids_to_process:
                # log.debug('Skipping id checking of [%s]' % str(elem_id))
                continue
            parent = current.getparent()
            parent_id = parent.get('id')
            if parent_id == tlo_id:
                # IndicatorItem node is a child of the top level OR node
                ids_to_process.add(elem_id)
            else:
                # IndicatorItem node is a child of a different Indicator
                while parent_id != tlo_id:
                    parent = current.getparent()
                    parent_id = parent.get('id')
                    if parent_id == tlo_id:
                        current_id = current.get('id')
                    else:
                        current = parent
                if current_id not in ids_to_process:
                    current_ids_set = set(current.xpath('.//@id'))
                    ids_to_process = ids_to_process.union(current_ids_set)
        # add the tlo_id to the set of ids to process.  It is possible for it
        # to have parameters attached to it which may affect yara processing
        if len(ids_to_process) == 0:
            return None
        ids_to_process.add(tlo_id)
        condition_string = self.get_yara_condition_string(ioc_obj.top_level_indicator, ioc_obj.parameters,
                                                          ids_to_process)
        return condition_string

    def get_yara_condition_string(self, indicator_node, parameters_node, ids_to_process, condition_string='',
                                  joining_value='or'):
        """
        get_yara_condition_string

        input
            indicator_node: this is the node we walk down
            parameters_node: this contains all the parameters in the ioc, so we
                can look up parameters nodes as we walk them.
            ids_to_process: set of ids to upgrade
            condition_string: This represnts the yara condition string.  This
                string grows as we walk nodes.
        return
            returns True upon completion
            may raise ValueError
        """

        indicator_node_id = str(indicator_node.get('id'))
        if indicator_node_id not in ids_to_process:
            msg = 'Entered into get_yara_condition_string with a invalid node to walk [[}]'.format(indicator_node_id)
            raise YaraConversionError(msg)
        expected_tag = 'Indicator'
        if indicator_node.tag != expected_tag:
            raise YaraConversionError('indicator_node expected tag is [%s]' % expected_tag)
        is_set = None
        # print 'indicator node id [%s]' % str(indicator_node_id)
        for param in parameters_node.xpath('.//param[@ref-id="{}"]'.format(indicator_node_id)):
            if param.attrib['name'] == 'yara/set':
                is_set = True
                set_count = param.findtext('value', None)
                try:
                    temp = int(set_count)
                    if temp < 1:
                        raise YaraConversionError('yara/set parameter value was less than 1')
                    if temp > len(indicator_node.getchildren()):
                        msg = 'yara/set value is greater than the number of children' \
                              ' of Indicator node [%s]' % str(indicator_node_id)
                        raise YaraConversionError(msg)
                except ValueError:
                    raise YaraConversionError('yara/set parameter was not a integer')
                set_dict = {'set_count': set_count, 'set_ids': []}

        for node in indicator_node.getchildren():
            node_id = node.get('id')
            # XXX strip out '-' characters from the ids.  If a guid is used as
            # the id, this will cause processing errors
            safe_node_id = node_id.replace('-', '')
            if node_id not in ids_to_process:
                continue
            if node.tag == 'IndicatorItem':
                # print 'handling indicatoritem: [%s]' % node_id
                if is_set:
                    set_dict['set_ids'].append('$' + safe_node_id)
                else:
                    # Default mapping
                    mapping = {'prefix': '$', 'identifier': safe_node_id, 'condition': '', 'postfix': ''}
                    # XXX: Alot of this could raise ValueError
                    use_condition_template = False
                    negation = node.get('negate')
                    condition = node.get('condition')
                    search = node.xpath('Context/@search')[0]
                    content = node.findtext('Content')

                    yara_condition = self.condition_to_yara_map[condition]
                    if not yara_condition:
                        msg = 'Invalid IndicatorItem condition encountered [%s][%s]' % (str(node_id), str(condition))
                        raise YaraConversionError(msg)
                    if negation.lower() == 'true':
                        negation = True
                    else:
                        negation = False
                    # parameters cannot modifier the condition of FileSize or Rule
                    if search == 'Yara/FileSize':
                        mapping['prefix'] = ''
                        mapping['identifier'] = 'filesize'
                        mapping['postfix'] = ' ' + content
                        mapping['condition'] = yara_condition
                        use_condition_template = True
                    elif search == 'Yara/RuleName':
                        if content not in self.ioc_names_set:
                            if mangle_name(content) in self.ioc_names_mangled_set:
                                msg = 'Yara/RuleName is present as a mangled name.[{}][{}]'.format(mangle_name(content),
                                                                                                   node_id)
                                log.warning(msg)
                                content = mangle_name(content)
                            else:
                                log.warning('Yara/RuleName points to a name [{}] that is not in the set of IOCs being'
                                            ' processed [{}]'.format(content, node_id))
                        if mangle_name(content) != content:
                            msg = 'Yara/RuleName contains characters which would cause libyara errors' \
                                  ' [{}]'.format(node_id)
                            raise YaraConversionError(msg)
                        mapping['prefix'] = ''
                        mapping['identifier'] = content
                    # handle parameters
                    else:
                        xp = './/param[@ref-id="{}" and (@name="yara/count" or @name="yara/offset/at" or' \
                             ' @name="yara/offset/in")]'.format(node_id)
                        params = parameters_node.xpath(xp)
                        if len(params) > 1:
                            msg = 'More than one condition parameters assigned to IndicatorItem [{}]'.format(node_id)
                            raise YaraConversionError(msg)
                        for param in params:
                            param_name = param.get('name', None)
                            if param_name == 'yara/count':
                                log.debug('Found [%s] attached to [%s]' % (param.attrib['name'], node_id))
                                mapping['prefix'] = '#'
                                mapping['postfix'] = ' ' + param.findtext('value')
                                mapping['condition'] = yara_condition
                                use_condition_template = True
                                break
                            elif param_name == 'yara/offset/at':
                                log.debug('Found [%s] attached to [%s]' % (param.attrib['name'], node_id))
                                mapping['condition'] = 'at'
                                mapping['postfix'] = ' ' + param.findtext('value')
                                use_condition_template = True
                                break
                            elif param_name == 'yara/offset/in':
                                log.debug('Found [%s] attached to [%s]' % (param.attrib['name'], node_id))
                                mapping['condition'] = 'in'
                                mapping['postfix'] = ' ' + param.findtext('value')
                                use_condition_template = True
                                break

                    if use_condition_template:
                        temp_string = self.yara_II_condition_template % mapping
                    else:
                        temp_string = self.yara_II_template % mapping

                    if condition_string == '':
                        condition_string = temp_string
                    else:
                        condition_string = ' '.join([condition_string, joining_value, temp_string])
                        # print condition_string

            elif node.tag == 'Indicator':
                if is_set:
                    raise YaraConversionError('Cannot have Indicator nodes underneath a Indicator node with yara/set')
                operator = node.get('operator').lower()
                if operator not in ['or', 'and']:
                    raise YaraConversionError('Indicator@operator is not and/or. [%s] has [%s]' % (id, operator))
                # handle parameters
                # XXX Temp POC
                recursed_condition = self.get_yara_condition_string(node, parameters_node, ids_to_process, '', operator)
                xp = './/param[@ref-id="{}" and @name="yara/set"]'.format(node_id)
                if (not parameters_node.xpath(xp)) and has_siblings(node):
                    recursed_condition = '(%s)' % recursed_condition

                if condition_string == '':
                    condition_string = recursed_condition
                else:
                    condition_string = ' '.join([condition_string, joining_value, recursed_condition])
                    # print 'recursed got: [%s]' % condition_string
            else:
                # should never get here
                raise YaraConversionError('node.tag is not a Indicator/IndicatorItem [%s]' % str(id))

        if is_set:
            log.debug('Building set expression for [%s]' % indicator_node_id)
            if len(set_dict['set_ids']) == 0:
                raise YaraConversionError('yara/set processing did not yield any set ids')
            elif len(set_dict['set_ids']) == 1:
                log.warning('yara/set with 1 id found for node [%s]' % node_id)
                set_ids = ''.join(set_dict['set_ids'])
            else:
                set_ids = ','.join(set_dict['set_ids'])
            set_dict['set_ids'] = set_ids
            temp_set_string = self.yara_set_string_template % set_dict
            # print temp_set_string
            if condition_string == '':
                condition_string = temp_set_string
            else:
                condition_string = ' '.join(
                    [condition_string, indicator_node.getparent().get('operator').lower(), temp_set_string])

        return condition_string

    def get_yara_stringlist(self, iocid):
        stringlist = []

        ioc_obj = self.iocs[iocid]
        xp = './/IndicatorItem[Context/@search = "Yara/HexString" or Context/@search = "Yara/TextString" or Context/@search = "Yara/RegexString" or Context/@search = "FileItem/Md5sum"'\
             ' or Context/@search = "Network/URI" or Context/@search = "Network/DNS"' \
             ' or Context/@search = "RegistryItem/ValueName" or Context/@search = "RegistryItem/Text"' \
             ' or Context/@search = "DnsEntryItem/RecordName" or Context/@search = "DnsEntryItem/Host"' \
             ' or Context/@search = "ProcessItem/HandleList/Handle/Name" or Context/@search = "ProcessItem/name"' \
             ' or Context/@search = "FileItem/FileName" or Context/@search = "PortItem/remoteIP"' \
             ' or Context/@search = "FileItem/Sha1sum" or Context/@search = "FileItem/Sha256sum" or Context/@search = "RegistryItem/Path"' \
             ' or Context/@search = "FileItem/SizeInBytes" or Context/@search = "FileItem/PEInfo/PETimeStamp" or Context/@search = "FileItem/FullPath"'\
             ' or Context/@search = "FileItem/PEInfo/DigitalSignature/CertificateSubject" or Context/@search = "ProcessItem/SectionList/MemorySection/Name"'\
             ' or Context/@search = "FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Name" or Context/@search = "RegistryItem/KeyPath" or Context/@search = "ProcessItem/arguments"'\
             ' or Context/@search = "FileItem/PEInfo/VersionInfoList/VersionInfoItem/OriginalFilename" or Context/@search = "FileItem/PEInfo/ImportedModules/Module/Name"'\
             ' or Context/@search = "Snort/Snort" or Context/@search = "ProcessItem/SectionList/MemorySection/PEInfo/Exports/DllName"'\
             ' or Context/@search = "FileItem/PEInfo/Exports/NumberOfFunctions" or Context/@search = "FileItem/PEInfo/Exports/ExportedFunctions/string" or Context/@search = "FileItem/PEInfo/VersionInfoList/VersionInfoItem/FileDescription"'\
             ' or Context/@search = "FileItem/StringList/string" or Context/@search = "TaskItem/ActionList/Action/ExecProgramPath" or Context/@search = "TaskItem/TriggerList/Trigger/TriggerFrequency"'\
             ' or Context/@search = "TaskItem/AccountName" ]'
        for node in ioc_obj.top_level_indicator.xpath(xp):
            modifiers = []

            node_id = node.get('id')
            # print node_id
            condition = node.get('condition')
            context_node = node.find('Context')
            content_node = node.find('Content')
            context = context_node.get('search')

            params = ioc_obj.parameters.xpath(
                './/param[@ref-id="%s" and (@name="yara/wide" or @name="yara/ascii" or @name="yara/fullword")]' % str(
                    node_id))
            pc = node.get('preserve-case', None)

            if context == 'Yara/TextString' or context == 'Yara/RegexString':
                if pc.lower() == 'false':
                    modifiers.append('nocase')
                for param in params:
                    name = param.get('name', None)
                    if name in self.yara_string_modifier_map:
                        modifiers.append(self.yara_string_modifier_map[name])
                string_modifier = ' '.join(modifiers)
            elif context == 'FileItem/SizeInBytes':
                #yara recognzies 'filesize' and then the number
                content_node.text = "filesize " + content_node.text +"B"
            elif context == 'FileItem/FileName' or context == 'FileItem/FullPath':
                with open(r'..\..\..\signature-base\misc-txt\filename-iocs.txt', "a") as iocfile:
                    iocfile.write(content_node.text)
                iocfile.close()
            elif context == 'FileItem/Md5sum' or context == 'FileItem/Sha1sum' or context == 'FileItem/Sha256sum':
                with open(r'..\..\..\signature-base\misc-txt\hashes.txt', "a") as hashfile:
                    hashfile.write(content_node.text)
                hashfile.close()
            else:
                string_modifier = ''
                indicator_content = content_node.text
                # strip out '-' characters from the ids.  If a guid is used as
                # the id, this will cause processing errors
                node_id = node_id.replace('-', '')
                mapping = {'string_id': node_id, 'content': indicator_content, 'modifiers': string_modifier}
                # print mapping
                # print context
                temp_string = self.yara_string_map[context] % mapping
                #print temp_string
                stringlist.append(temp_string)

        # build data for yara
        yara_string = ''
        for row in stringlist:
            yara_string += '        %s\n' % row

        return yara_string

    def get_yara_metadata(self, iocid):
        metadata = []
        ioc_obj = self.iocs[iocid]
        for key in self.metadata_fields:
            value = ioc_obj.metadata.findtext(key, None)
            if value:
                # cleanup linebreaks
                value = value.replace('\n', ' ').replace('\r', ' ')
                temp_string = '%s = "%s"' % (str(key), str(value))
                metadata.append(temp_string)
        for link in ioc_obj.metadata.xpath('.//link'):
            rel = link.get('rel', None)
            if not rel:
                raise YaraConversionError('link node without rel attribute [%s] is not schema compliant' % (str(iocid)))
            href = link.get('href', None)
            text = link.text
            if text and href:
                value = '%s = "%s %s"' % (rel, text, href)
            elif text and not href:
                value = '%s = "%s"' % (rel, text)
            elif not text and href:
                value = '%s = "%s"' % (rel, href)
            else:
                value = 'link = "%s"' % rel
            metadata.append(value)
            # cleanup linebreaks,
        # add iocid
        metadata.append('iocid = "%s"' % str(iocid))
        # build data for yara
        yara_string = ''
        for row in metadata:
            yara_string += '        %s\n' % row
        return yara_string

    def write_yara(self, output_file):
        """
        Write out yara signatures to a file.
        """
        fout = open(output_file, 'wb')
        fout.write('\n')

        for iocid in self.yara_signatures:
            signature = self.yara_signatures[iocid]
            fout.write(signature)
            fout.write('\n')

        fout.close()
        return True


def mangle_name(name):
    # cannot have certain characters in the name, causes libyara errors.
    new_name = str(name)
    chars_to_replace = [(' ', '_'), ('(', '_'), (')', '_')]
    for pair in chars_to_replace:
        src, dest = pair
        new_name = new_name.replace(src, dest)
    return new_name


def has_siblings(node):
    if node.getnext() is not None or node.getprevious() is not None:
        return True
    else:
        return False


def main(options):
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s: %(message)s  [%(filename)s:%(funcName)s]')
    if not options.verbose:
        logging.disable(logging.DEBUG)

    output_file = os.path.abspath(options.output)
    if output_file:
        if os.path.isdir(output_file):
            log.error('cannot specify a directory as the output location')
            sys.exit(1)
        elif not os.path.isfile(output_file):
            utils.safe_makedirs(os.path.split(output_file)[0])
    else:
        output_file = os.path.join(os.getcwd(), 'iocs.yara')
        log.info('Output not specified. Writing output to [{}]'.format(output_file))

    iocm = YaraIOCManager()
    iocm.insert(options.iocs)
    if len(iocm) < 0:
        log.error('No IOCs inserted into ioc_manager')
        sys.exit(1)
    iocm.emit_yara()
    iocm.write_yara(output_file)

    sys.exit(0)


def makeargpaser():
    parser = argparse.ArgumentParser(description='Convert .ioc files with YARA signatures embedded in them into'
                                                 ' .yara files.')
    parser.add_argument('-i', '--iocs', dest='iocs', required=True, type=str,
                        help='Directory to iocs or the ioc to process.')
    parser.add_argument('-o', '--output', dest='output', default=None,
                        help='File to write yara signatures too.  This will overwrite an existing file.  By default, '
                             'this is "iocs.yara"')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Verbose output', default=None)
    return parser


if __name__ == "__main__":
    p = makeargpaser()
    opts = p.parse_args()
    main(opts)
