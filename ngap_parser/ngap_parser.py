import os
import sys
import json
import csv
import argparse
import jsonpath
import pandas as pd

from collections import defaultdict

from ngap_ue import NGAPConstant
from ngap_ue import UENGAPFLow

def read_json(filename):
    with open(filename, 'r', encoding='utf-8') as in_file:
        data = json.load(in_file, object_pairs_hook = obj_pairs_hook)
        return data

def obj_pairs_hook(lst):
    result={}
    count={}
    for key,val in lst:
        if key in count:count[key]=1+count[key]
        else:count[key]=1
        if key in result:
            if count[key] > 2:
                result[key].append(val)
            else:
                result[key]=[result[key], val]
        else:
            result[key]=val
    return result
    
def get_values_by_key(obj, key):
    # 递归查找 JSON 中所有匹配的 key 对应的 value 
    results = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                results.append(v)
            if isinstance(v, (dict, list)):
                results.extend(get_values_by_key(v, key))
    elif isinstance(obj, list):
        for item in obj:
            results.extend(get_values_by_key(item, key))
    return results 

def save_dict_to_csv(data_list, out_file, label):
    df_list = []
    if len(data_list) == 0:
        return
    
    for ue_features in data_list:
        ue_features.padding_cut_for_seq(NGAPConstant.SEQ_MAX_LENgth)
        flow = ue_features.to_dict()
        df_list.append(flow)

    header = df_list[0].keys()
    dataset = pd.DataFrame(df_list, columns=header)
    if os.path.exists(out_file):
        dataset.to_csv(out_file, index=False, mode="a", header=False)
    else:
        dataset.to_csv(out_file, index=False, mode="w")

def parse_nas_msg(nas_msg, ue_flow): 
    for item_key in nas_msg:
        sec_header_type = ""
        if 'Security protected NAS 5GS message' in item_key:
            sec_nas_msg = nas_msg.get(item_key)

            if sec_header_type == "":
                sec_header_type = sec_nas_msg.get('nas_5gs.security_header_type')
                ue_flow.nas_sec_seq.append(int(sec_header_type))

            seq_no = sec_nas_msg.get('nas_5gs.seq_no')
            ue_flow.seq_no.append(int(seq_no))

        elif 'Plain NAS 5GS Message' in item_key:
            plain_nas_msg = nas_msg.get(item_key)

            if sec_header_type == "":
                sec_header_type = plain_nas_msg.get('nas_5gs.security_header_type')
                if sec_header_type != None:
                    ue_flow.nas_sec_seq.append(int(sec_header_type))

            nas_msg_type_str = plain_nas_msg.get('nas_5gs.mm.message_type')
            if nas_msg_type_str == None:
                nas_msg_type_str = plain_nas_msg.get('nas_5gs.sm.message_type')
            if nas_msg_type_str == None:
                continue
            nas_msg_type = int(nas_msg_type_str)
            ue_flow.nas_type_seq.append(nas_msg_type)

            # Extract IE Feature
            if nas_msg_type == NGAPConstant.id_registration_request:
                ue_flow.ue_status = NGAPConstant.ID_REGISTERED_INITIATED

                mmfor = plain_nas_msg.get('5GS registration type') \
                                .get('nas_5gs.mm.for')
                ue_flow.mmfor = int(mmfor)
                reg_type = plain_nas_msg.get('5GS registration type') \
                                .get('nas_5gs.mm.5gs_reg_type')
                ue_flow.reg_type = int(reg_type)

                tsc = plain_nas_msg.get('NAS key set identifier') \
                                .get('nas_5gs.mm.tsc.h1')
                ue_flow.tsc = int(tsc)
                nas_key_set_id = plain_nas_msg.get('NAS key set identifier') \
                                .get('nas_5gs.mm.nas_key_set_id.h1')
                ue_flow.nas_key_set_id = int(nas_key_set_id)
                
                supi_fmt = plain_nas_msg.get('5GS mobile identity') \
                                .get('nas_5gs.mm.suci.supi_fmt')
                if supi_fmt != None:
                    ue_flow.supi_fmt = int(supi_fmt)
                type_id = plain_nas_msg.get('5GS mobile identity') \
                                        .get('nas_5gs.mm.type_id')
                if type_id != None:
                    ue_flow.type_id = int(type_id)

            elif nas_msg_type == NGAPConstant.id_registration_accept:
                reg_result = plain_nas_msg.get('5GS registration result')
                nssaa_perf = reg_result.get('nas_5gs.mm.reg_res.nssaa_perf')
                ue_flow.nssaa_perf = int(nssaa_perf)
                sms_all = reg_result.get('nas_5gs.mm.reg_res.sms_all')
                ue_flow.sms_all = int(sms_all)
                res = reg_result.get('nas_5gs.mm.reg_res.res')
                ue_flow.reg_result = int(res)

                feature = plain_nas_msg.get('5GS network feature support')
                mpsi = feature.get('nas_5gs.nw_feat_sup.mpsi')
                ue_flow.mpsi = int(mpsi)
                iwk_n26 = feature.get('nas_5gs.nw_feat_sup.iwk_n26')
                ue_flow.iwk_n26 = int(iwk_n26)
                emf = feature.get('nas_5gs.nw_feat_sup.emf')
                ue_flow.emf = int(emf)
                emc = feature.get('nas_5gs.nw_feat_sup.emc')
                ue_flow.emc = int(emc)
                vops_n3gpp = feature.get('nas_5gs.nw_feat_sup.vops_n3gpp')
                ue_flow.vops_n3gpp = int(vops_n3gpp)
                vops_3gpp = feature.get('nas_5gs.nw_feat_sup.vops_3gpp')
                ue_flow.vops_3gpp = int(vops_3gpp)
                spare_b7 = feature.get('nas_5gs.spare_b7')
                if spare_b7 == None:
                    continue
                ue_flow.up_ciot = int(spare_b7)
                spare_b6 = feature.get('nas_5gs.spare_b6')
                ue_flow.iphc_cp_ciot = int(spare_b6)
                spare_b5 = feature.get('nas_5gs.spare_b5')
                ue_flow.n3_data = int(spare_b5)
                spare_b4 = feature.get('nas_5gs.spare_b4')
                ue_flow.cp_ciot = int(spare_b4)
                spare_b3 = feature.get('nas_5gs.spare_b3')
                spare_b2 = feature.get('nas_5gs.spare_b2')
                ue_flow.restrictec = int(spare_b3+spare_b2)
                mcsi = feature.get('nas_5gs.nw_feat_sup.mcsi')
                ue_flow.mcsi = int(mcsi)
                emcn3 = feature.get('nas_5gs.nw_feat_sup.emcn3')
                ue_flow.emcn3 = int(emcn3)

            elif nas_msg_type == NGAPConstant.id_registration_complete:
                pass

            elif nas_msg_type == NGAPConstant.id_registration_reject:
                ue_flow.ue_status = NGAPConstant.ID_DEREGISTERED
                mm_cause = plain_nas_msg.get('5GMM cause') \
                                        .get('nas_5gs.mm.5gmm_cause')
                ue_flow.mm_cause = int(mm_cause)
            
            elif nas_msg_type == NGAPConstant.id_deregistration_request_ue_originating:
                switch_off = plain_nas_msg.get('De-registration type') \
                                        .get('nas_5gs.mm.switch_off')
                ue_flow.switch_off = int(switch_off)
                re_reg_req = plain_nas_msg.get('De-registration type') \
                                        .get('nas_5gs.mm.re_reg_req')
                ue_flow.re_reg_req = int(re_reg_req)
                acc_type = plain_nas_msg.get('De-registration type') \
                                        .get('nas_5gs.mm.acc_type')
                ue_flow.acc_type = int(acc_type)
            
            elif nas_msg_type == NGAPConstant.id_deregistration_accept_ue_originating:
                ue_flow.ue_status = NGAPConstant.ID_DEREGISTERED

            elif nas_msg_type == NGAPConstant.id_deregistration_accept_ue_terminated:
                ue_flow.ue_status = NGAPConstant.ID_DEREGISTERED
            
            elif nas_msg_type == NGAPConstant.id_service_request:
                ue_flow.ue_status = NGAPConstant.ID_REGISTERED_INITIATED
                serv_type = plain_nas_msg.get('Service type') \
                                        .get('nas_5gs.mm.serv_type')
                ue_flow.serv_type = int(serv_type)

            elif nas_msg_type == NGAPConstant.id_service_reject:
                ue_flow.ue_status = NGAPConstant.ID_DEREGISTERED

            elif nas_msg_type == NGAPConstant.id_service_accept:
                ue_flow.ue_status = NGAPConstant.ID_REGISTERED

            elif nas_msg_type == NGAPConstant.id_authentication_request:
                abba = plain_nas_msg.get('ABBA').get('nas_5gs.mm.abba_contents')
                ue_flow.abba = int(abba, 16)

            elif nas_msg_type == NGAPConstant.id_authentication_response:
                pass

            elif nas_msg_type == NGAPConstant.id_authentication_reject:
                pass

            elif nas_msg_type == NGAPConstant.id_authentication_failure:
                pass

            elif nas_msg_type == NGAPConstant.id_security_mode_command:
                nas_sec_algo_enc = plain_nas_msg.get('NAS security algorithms') \
                            .get('nas_5gs.mm.nas_sec_algo_enc')
                nas_sec_algo_ip = plain_nas_msg.get('NAS security algorithms') \
                            .get('nas_5gs.mm.nas_sec_algo_ip')
                ue_flow.cipher_alg = int(nas_sec_algo_enc)
                ue_flow.integrity_alg = int(nas_sec_algo_ip)

            elif nas_msg_type == NGAPConstant.id_security_mode_complete:
                ue_flow.ue_status = NGAPConstant.ID_REGISTERED

            elif nas_msg_type == NGAPConstant.id_security_mode_reject:
                ue_flow.ue_status = NGAPConstant.ID_DEREGISTERED

            elif nas_msg_type == NGAPConstant.id_pdu_session_establishment_request:
                int_prot_max_data_rate = plain_nas_msg.get('Integrity protection maximum data rate')
                ue_flow.max_data_rate_ul = int(int_prot_max_data_rate.get('nas_5gs.sm.int_prot_max_data_rate_ul'))
                ue_flow.max_data_rate_dl = int(int_prot_max_data_rate.get('nas_5gs.sm.int_prot_max_data_rate_dl'))

            elif nas_msg_type == NGAPConstant.id_pdu_session_establishment_accept:
                sel_sc_mode = plain_nas_msg.get('nas_5gs.sm.sel_sc_mode')
                ue_flow.sel_sc_mode = int(sel_sc_mode)
                pdu_session_type = plain_nas_msg.get('PDU session type - Selected PDU session type') \
                                            .get('nas_5gs.sm.pdu_session_type')
                ue_flow.pdu_session_type = int(pdu_session_type)
            
            elif nas_msg_type == NGAPConstant.id_pdu_session_establishment_reject:
                ue_flow.ue_status = NGAPConstant.ID_DEREGISTERED

            elif nas_msg_type == NGAPConstant.id_pdu_session_release_request:
                pass

            elif nas_msg_type == NGAPConstant.id_pdu_session_release_command:
                sm_cause = plain_nas_msg.get('5GSM cause').get('nas_5gs.sm.5gsm_cause')
                ue_flow.sm_cause = int(sm_cause)
            
            elif nas_msg_type == NGAPConstant.id_pdu_session_release_complete:
                ue_flow.ue_status = NGAPConstant.ID_DEREGISTERED

            elif nas_msg_type == NGAPConstant.id_ul_nas_transport:
                second_nas = plain_nas_msg.get('Payload container')
                parse_nas_msg(second_nas, ue_flow)

            elif nas_msg_type == NGAPConstant.id_dl_nas_transport:
                second_nas = plain_nas_msg.get('Payload container')
                parse_nas_msg(second_nas, ue_flow)
            
            elif nas_msg_type == NGAPConstant.id_configuration_update_command:
                zone = plain_nas_msg.get('Time Zone - Local')
                if zone == None:
                    zone = plain_nas_msg.get('Time Zone and Time - Universal Time and Local Time Zone')
                timezone = zone.get('gsm_a.dtap.timezone')
                ue_flow.timezone = int(timezone, 16)

            elif nas_msg_type == NGAPConstant.id_configuration_update_complete:
                pass

            elif nas_msg_type == NGAPConstant.id_identity_request:
                pass

            elif nas_msg_type == NGAPConstant.id_identity_response:
                pass

            elif nas_msg_type == NGAPConstant.id_not_use_in_current_version:
                pass

            else:
                raise NameError('Not Found NAS Message Type Error:', nas_msg_type)

            for key in plain_nas_msg:
                if 'NAS message container' in key:
                    second_nas_msg = plain_nas_msg.get('NAS message container') \
                                                .get('nas-5gs')
                    parse_nas_msg(second_nas_msg, ue_flow)
        
def parse_ngap_msg(ngap_msg, ue_flow):
    nagp_tree = ngap_msg.get('ngap.protocolIEs_tree')

    for item_key in nagp_tree:
        item = nagp_tree.get(item_key)

        # Parse ngap message
        if 'id-AMF-UE-NGAP-ID' in item_key:
            pass
        elif 'id-RAN-UE-NGAP-ID' in item_key:
            pass

        elif 'id-NAS-PDU' in item_key:
            nas_msg = item.get('ngap.ProtocolIE_Field_element') \
                            .get('ngap.value_element') \
                            .get('ngap.NAS_PDU_tree') \
                            .get('nas-5gs')
            parse_nas_msg(nas_msg, ue_flow)

        elif 'id-UserLocationInformation' in item_key:
            userlocatinfo = item.get('ngap.ProtocolIE_Field_element') \
                        .get('ngap.value_element') \
                        .get('ngap.UserLocationInformation_tree') \
                        .get('ngap.userLocationInformationNR_element')
            if userlocatinfo == None:
                continue

            plmn = userlocatinfo.get('ngap.nR_CGI_element') \
                                .get('ngap.pLMNIdentity_tree')
            if ue_flow.mcc == -1:
                ue_flow.mcc = int(plmn.get('e212.mcc'))
                ue_flow.mnc = int(plmn.get('e212.mnc'))
            
            cell_id = userlocatinfo.get('ngap.nR_CGI_element') \
                                  .get('ngap.NRCellIdentity')
            ue_flow.cell_id_seq.append(int(cell_id, 16))
            tac = userlocatinfo.get('ngap.tAI_element').get('ngap.tAC')
            ue_flow.tac_seq.append(int(tac, 16))
            time = userlocatinfo.get('ngap.timeStamp')
            if time != None:
                ue_flow.time_seq.append(int(time.replace(':', ''), 16))
            
        elif 'id-RRCEstablishmentCause' in item_key:
            cause = item.get('ngap.ProtocolIE_Field_element') \
                        .get('ngap.value_element') \
                        .get('ngap.RRCEstablishmentCause')
            ue_flow.establish_cause = int(cause, 16)

        elif 'id-UESecurityCapabilities' in item_key:
            ue_capa = item.get('ngap.ProtocolIE_Field_element') \
                        .get('ngap.value_element') \
                        .get('ngap.UESecurityCapabilities_element')
            nRencryption = ue_capa.get('ngap.nRencryptionAlgorithms')
            ue_flow.nRencryption = (int(nRencryption.replace(':', ''), 16))
            nRintegrityProtection = ue_capa.get('ngap.nRintegrityProtectionAlgorithms')
            ue_flow.nRintegrityProtection = (int(nRintegrityProtection.replace(':', ''), 16))
            eUTRAencryption = ue_capa.get('ngap.eUTRAencryptionAlgorithms')
            ue_flow.eUTRAencryption = (int(eUTRAencryption.replace(':', ''), 16))
            eUTRAintegrityProtection = ue_capa.get('ngap.eUTRAintegrityProtectionAlgorithms')
            ue_flow.eUTRAintegrityProtection = (int(eUTRAintegrityProtection.replace(':', ''), 16))
        
        elif 'id-Cause' in item_key:
            cause_nas = item.get('ngap.ProtocolIE_Field_element') \
                        .get('ngap.value_element') \
                        .get('ngap.Cause_tree') \
                        .get('ngap.nas')
            if cause_nas != None:
                ue_flow.cause_nas = cause_nas

        elif 'id-PDUSessionResourceSetupListSUReq' in item_key:
            pdu_req_elem = item.get('ngap.ProtocolIE_Field_element') \
                        .get('ngap.value_element') \
                        .get('ngap.PDUSessionResourceSetupListSUReq_tree') \
                        .get('Item 0') \
                        .get('ngap.PDUSessionResourceSetupItemSUReq_element')
            nas_5gs = pdu_req_elem.get('ngap.pDUSessionNAS_PDU_tree').get('nas-5gs')
            parse_nas_msg(nas_5gs, ue_flow)

def parse_nagp_by_type(ngap_msg, ue_flow):
    ngap_type = int(ngap_msg.get('ngap.NGAP_PDU'))
    if ngap_type == NGAPConstant.id_InitiatingMessage: 
        # initiatingMessage
        init_msg = ngap_msg.get('ngap.NGAP_PDU_tree') \
                            .get('ngap.initiatingMessage_element')
        procedureCode = int(init_msg.get('ngap.procedureCode'))
        ue_flow.procedurecode_seq.append(procedureCode)

        if procedureCode == NGAPConstant.id_NGSetup:
            ng_setup_req = init_msg.get('ngap.value_element') \
                            .get('ngap.NGSetupRequest_element')
        
        elif procedureCode == NGAPConstant.id_InitialUEMessage:
            init_ue_msg = init_msg.get('ngap.value_element') \
                            .get('ngap.InitialUEMessage_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_InitialUEMessage)
            parse_ngap_msg(init_ue_msg, ue_flow)

        elif procedureCode == NGAPConstant.id_DownlinkNASTransport:
            down_nas_tran = init_msg.get('ngap.value_element') \
                            .get('ngap.DownlinkNASTransport_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Downlink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_DownlinkNASTransport)    
            parse_ngap_msg(down_nas_tran, ue_flow)
        
        elif procedureCode == NGAPConstant.id_UplinkNASTransport:
            up_nas_tran = init_msg.get('ngap.value_element') \
                            .get('ngap.UplinkNASTransport_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_UplinkNASTransport)    
            parse_ngap_msg(up_nas_tran, ue_flow)
        
        elif procedureCode == NGAPConstant.id_InitialContextSetup:
            init_con_setup_req = init_msg.get('ngap.value_element') \
                            .get('ngap.InitialContextSetupRequest_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Downlink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_InitialContextSetupRequest)    
            parse_ngap_msg(init_con_setup_req, ue_flow)
        
        elif procedureCode == NGAPConstant.id_PDUSessionResourceSetup:
            pdu_ses_res_setup_req = init_msg.get('ngap.value_element') \
                            .get('ngap.PDUSessionResourceSetupRequest_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Downlink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_PDUSessionResourceSetupRequest)    
            parse_ngap_msg(pdu_ses_res_setup_req, ue_flow)
        
        elif procedureCode == NGAPConstant.id_PDUSessionResourceRelease:
            pdu_ses_res_relea_com = init_msg.get('ngap.value_element') \
                            .get('ngap.PDUSessionResourceReleaseCommand_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Downlink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_PDUSessionResourceRelease)    
            parse_ngap_msg(pdu_ses_res_relea_com, ue_flow)
        
        elif procedureCode == NGAPConstant.id_UEContextRelease:
            ue_con_relea_command = init_msg.get('ngap.value_element') \
                            .get('ngap.UEContextReleaseCommand_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Downlink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_UEContextReleaseCommand)  
            parse_ngap_msg(ue_con_relea_command, ue_flow)

        elif procedureCode == NGAPConstant.id_UEContextReleaseRequest:
            ue_cont_relea_req = init_msg.get('ngap.value_element') \
                            .get('ngap.UEContextReleaseRequest_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_UEContextReleaseRequest)  
            parse_ngap_msg(ue_cont_relea_req, ue_flow)

        elif procedureCode == NGAPConstant.id_UERadioCapabilityInfoIndication:
            ue_radio_capa_info = init_msg.get('ngap.value_element') \
                            .get('ngap.UERadioCapabilityInfoIndication_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_UERadioCapabilityInfoIndication)  
            parse_ngap_msg(ue_radio_capa_info, ue_flow)

        elif procedureCode == NGAPConstant.id_ErrorIndication:
            error_indication = init_msg.get('ngap.value_element') \
                            .get('ngap.ErrorIndication_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_ErrorIndication)  
            parse_ngap_msg(error_indication, ue_flow)

        elif procedureCode == NGAPConstant.id_PathSwitchRequest:
            path_switch_req = error_indication = init_msg.get('ngap.value_element') \
                                        .get('ngap.PathSwitchRequest_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_PathSwitchRequest)  
            parse_ngap_msg(path_switch_req, ue_flow)

        elif procedureCode == NGAPConstant.id_HandoverPreparation:
            handover_req = error_indication = init_msg.get('ngap.value_element') \
                                        .get('ngap.HandoverRequired_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_HandoverPreparation)  
            parse_ngap_msg(handover_req, ue_flow)

        elif procedureCode == NGAPConstant.id_HandoverResourceAllocation:
            handover_req = error_indication = init_msg.get('ngap.value_element') \
                                        .get('ngap.HandoverRequest_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Downlink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_HandoverResourceAllocation)  
            parse_ngap_msg(handover_req, ue_flow)
        
        elif procedureCode == NGAPConstant.id_HandoverNotification:
            handover_notify = error_indication = init_msg.get('ngap.value_element') \
                                        .get('ngap.HandoverNotify_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_HandoverNotification)  
            parse_ngap_msg(handover_notify, ue_flow)
        
        elif procedureCode == NGAPConstant.id_TraceFailureIndication:
            ue_flow.direc_seq.append(NGAPConstant.id_Downlink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_TraceFailureIndication)  
            
        elif procedureCode == NGAPConstant.id_RRCInactiveTransitionReport:
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_RRCInactiveTransitionReport)  
            
        elif procedureCode == NGAPConstant.id_LocationReportingFailureIndication:
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_LocationReportingFailureIndication)  

        elif procedureCode == NGAPConstant.id_HandoverCancel:
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_HandoverCancel) 

        elif procedureCode == NGAPConstant.id_NGReset:
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_NGReset)  
            
        elif procedureCode == NGAPConstant.id_UplinkRANStatusTransfer:
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_UplinkRANStatusTransfer)
            
        elif procedureCode == NGAPConstant.id_LocationReport:
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_LocationReport)
        
        elif procedureCode == NGAPConstant.id_HandoverPreparation:
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_HandoverPreparation)

        elif procedureCode == NGAPConstant.id_PDUSessionResourceModifyIndication:
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_PDUSessionResourceModifyIndication)

        elif procedureCode == NGAPConstant.id_UplinkUEAssociatedNRPPaTransport:
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_UplinkUEAssociatedNRPPaTransport)

        elif procedureCode == NGAPConstant.id_SecondaryRATDataUsageReport:
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_SecondaryRATDataUsageReport)

        elif procedureCode == NGAPConstant.id_PDUSessionResourceNotify:
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_PDUSessionResourceNotify)

        elif procedureCode == NGAPConstant.id_NASNonDeliveryIndication:
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_NASNonDeliveryIndication)
        
        elif procedureCode == NGAPConstant.id_CellTrafficTrace:
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_CellTrafficTrace)

        else:
            raise NameError('NGAP Message Type 2 Error:', procedureCode)

    elif ngap_type == NGAPConstant.id_SuccessfulOutcome:
        # successfulOutcome
        succ_out = ngap_msg.get('ngap.NGAP_PDU_tree') \
                            .get('ngap.successfulOutcome_element')
        procedureCode = int(succ_out.get('ngap.procedureCode'))
        ue_flow.procedurecode_seq.append(procedureCode)
        
        if procedureCode == NGAPConstant.id_NGSetup:
            ng_setup_res = succ_out.get('ngap.value_element') \
                            .get('ngap.NGSetupResponse_element')
                
        elif procedureCode == NGAPConstant.id_InitialContextSetup:
            init_con_setup_res = succ_out.get('ngap.value_element') \
                            .get('ngap.InitialContextSetupResponse_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_InitialContextSetupResponse)    
            parse_ngap_msg(init_con_setup_res, ue_flow)
        
        elif procedureCode == NGAPConstant.id_PDUSessionResourceSetup:
            pdu_ses_res_setup_res = succ_out.get('ngap.value_element') \
                            .get('ngap.PDUSessionResourceSetupResponse_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_PDUSessionResourceSetupResponse)    
            parse_ngap_msg(pdu_ses_res_setup_res, ue_flow)
        
        elif procedureCode == NGAPConstant.id_PDUSessionResourceRelease:
            pdu_ses_res_relea_res = succ_out.get('ngap.value_element') \
                            .get('ngap.PDUSessionResourceReleaseResponse_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_PDUSessionResourceRelease)    
            parse_ngap_msg(pdu_ses_res_relea_res, ue_flow)
            
        elif procedureCode == NGAPConstant.id_UEContextRelease:
            ue_con_relea_complete = succ_out.get('ngap.value_element') \
                            .get('ngap.UEContextReleaseComplete_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_UEContextReleaseComplete)  
            parse_ngap_msg(ue_con_relea_complete, ue_flow)
        
        elif procedureCode == NGAPConstant.id_PathSwitchRequest:
            path_switch_req_ack = succ_out.get('ngap.value_element') \
                            .get('ngap.PathSwitchRequestAcknowledge_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Downlink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_PathSwitchRequest)  
            parse_ngap_msg(path_switch_req_ack, ue_flow)

        elif procedureCode == NGAPConstant.id_HandoverPreparation:
            handover_command = succ_out.get('ngap.value_element') \
                            .get('ngap.HandoverCommand_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Downlink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_HandoverPreparation)  
            parse_ngap_msg(handover_command, ue_flow)

        elif procedureCode == NGAPConstant.id_HandoverResourceAllocation:
            handover_req_ack = succ_out.get('ngap.value_element') \
                            .get('ngap.HandoverRequestAcknowledge_element')
            ue_flow.direc_seq.append(NGAPConstant.id_Uplink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_HandoverResourceAllocation)  
            parse_ngap_msg(handover_req_ack, ue_flow)

        elif procedureCode == NGAPConstant.id_NGReset:
            ue_flow.direc_seq.append(NGAPConstant.id_Downlink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_NGReset)  

        else:
            raise NameError('NGAP Message Type 2 Error:', procedureCode)   
                    
    elif ngap_type == NGAPConstant.id_UnsuccessfulOutcome:
        # unsuccessfulOutcome
        unsucc_out = ngap_msg.get('ngap.NGAP_PDU_tree') \
                            .get('ngap.unsuccessfulOutcome_element')
        procedureCode = int(unsucc_out.get('ngap.procedureCode'))
        ue_flow.procedurecode_seq.append(procedureCode)
        
        if procedureCode == NGAPConstant.id_NGSetup:
            ng_setup_fail = unsucc_out.get('ngap.value_element') \
                    .get('ngap.NGSetupFailure_element')
            
        elif procedureCode == NGAPConstant.id_InitialContextSetup:
            init_con_setup_fail = unsucc_out.get('ngap.value_element') \
                            .get('ngap.InitialContextSetupFailure_element')    
            ue_flow.direc_seq.append(NGAPConstant.id_Downlink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_InitialContextSetupFailure)    
            parse_ngap_msg(init_con_setup_fail, ue_flow)

        elif procedureCode == NGAPConstant.id_HandoverPreparation:
            ue_flow.direc_seq.append(NGAPConstant.id_Downlink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_HandoverPreparation)    

        elif procedureCode == NGAPConstant.id_PathSwitchRequest:
            ue_flow.direc_seq.append(NGAPConstant.id_Downlink)
            ue_flow.ngap_type_seq.append(NGAPConstant.id_PathSwitchRequest) 

        else:
            raise NameError(' NGAP Message Type 2 Error:', procedureCode) 

    else:
        raise NameError('NGAP Message Type 1 Error:', ngap_type)

def parse_nagp_by_ue(in_file, out_file, label):
    # read json file
    data = read_json(in_file)
    flow_json_dict = defaultdict(list)
    ue_flow_list = []

    # packet group by ran_ue_ngap_id
    for packet in data:
        # NGAP Parse
        ngap_msg_list = jsonpath.jsonpath(packet, "$._source.layers.ngap")
        if ngap_msg_list == False:
            continue
        ngap_msg = ngap_msg_list[0]
        ran_ue_ngap_id = get_values_by_key(ngap_msg, "ngap.RAN_UE_NGAP_ID")
        if len(ran_ue_ngap_id) > 0:
            ran_ue_ngap_id = int(ran_ue_ngap_id[0])
            flow_json_dict[ran_ue_ngap_id].append(packet)
        else:
            # UEContextReleaseCommand_element
            ran_ue_ngap_id = get_values_by_key(ngap_msg, "ngap.rAN_UE_NGAP_ID")
            if len(ran_ue_ngap_id) > 0:
                ran_ue_ngap_id = int(ran_ue_ngap_id[0])
                flow_json_dict[ran_ue_ngap_id].append(packet)
            
    # feature extract
    for ue_id, flow_json in flow_json_dict.items():
        if len(flow_json) == 0:
            continue

        # UENGAPFLow stroe all features
        ue_flow = UENGAPFLow()
        ue_flow.ran_ngap_ue_id = ue_id
        ue_flow.label = label # Label

        ue_flow_max_length = NGAPConstant.SEQ_MAX_LENgth
        ue_flow_count = 0

        for packet in flow_json:
            # Anormaly Dataset Seq to 18 length
            ue_flow_count = ue_flow_count + 1
            if label == 1 and ue_flow_count > ue_flow_max_length:
                ue_flow_list.append(ue_flow)
                ue_flow = UENGAPFLow()
                ue_flow.ran_ngap_ue_id = ue_id
                ue_flow.label = label # Label
                ue_flow_count = 1

            # Frame
            timestamp = jsonpath.jsonpath(packet, "$._source.layers.frame")[0].get('frame.time_epoch')
            ue_flow.timestamp_seq.append(float(timestamp))

            # IP
            ip_msg = jsonpath.jsonpath(packet, "$._source.layers.ip")[0]
            if ue_flow.src_ip == "" and ue_flow.dst_ip == "":
                ue_flow.src_ip = ip_msg.get('ip.src')
                ue_flow.dst_ip = ip_msg.get('ip.dst')

            # SCTP
            sctp_msg = jsonpath.jsonpath(packet, "$._source.layers.sctp")[0]

            # NGAP
            ngap_msg = jsonpath.jsonpath(packet, "$._source.layers.ngap")[0]
            if (type(ngap_msg) == list):
                # Multiple NGAP
                for msg in ngap_msg:
                    parse_nagp_by_type(msg, ue_flow)
            else:
                # Single NGAP
                parse_nagp_by_type(ngap_msg, ue_flow)
                
        # Dict stroe all UENGAPFLow by RAN_NGAP_UE_ID
        ue_flow_list.append(ue_flow)

    # Save Dict to CSV File
    save_dict_to_csv(ue_flow_list, out_file, label)

    # jsonstr = json.dumps(ngap_tree, indent=4)
    # print(jsonstr)
 
# 使用示例
if __name__ == "__main__":
    # argument checking
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-f", "--file", help="Pcap(json format) file name")
    argparser.add_argument("-d", "--dir", help="Pcap(json format) file name")
    argparser.add_argument("-o", "--out", help="Out(csv format) file name")
    argparser.add_argument("-l", "--label", help="Type(normal-0/anormal-1) file name")
    args = argparser.parse_args()

    out_filename = args.out
    # out_filename = 'datasets/data.csv'

    label = int(args.label)
        
    if (args.file):
        # File
        in_filename = args.file
        idx = in_filename.rfind('/_json')
        ue_flow_dict = parse_nagp_by_ue(in_filename, out_filename, label)
        
    else:
        # Dir 
        path_name = args.dir 
        par_path_name = os.path.abspath(os.path.join(path_name, os.pardir))

        if not(os.path.isdir(path_name)):
            argparser.parse_args(['-h'])
            sys.exit()

        file_list = os.listdir(path_name) 
        for file_name in file_list:
            if file_name == ".DS_Store":
                continue
            read_file_name = path_name + "/" + file_name
            print("< NGAP Parse >>> " + read_file_name)
            parse_nagp_by_ue(read_file_name, out_filename, label)


    print(" ### finish ### ")
