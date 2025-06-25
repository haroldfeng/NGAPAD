import sys
from constant import *

class UENGAPFLow:
    def __init__(self):
        self.src_ip = ""
        self.dst_ip = ""
        self.ran_ngap_ue_id = -1

        # Label 
        self.label = -1

        # Time Sequence Feature
        self.timestamp_seq = []
        self.direc_seq = []
        self.procedurecode_seq = []
        self.ngap_type_seq = []
        self.nas_sec_seq = []
        self.nas_type_seq = []
        self.cell_id_seq = []
        self.tac_seq = []
        self.time_seq = []
        self.seq_no = []

        # IE Parameter Feature
        self.ue_status = NGAPConstant.ID_DEREGISTERED
        self.establish_cause = -1
        self.nRencryption = -1
        self.nRintegrityProtection = -1
        self.eUTRAencryption = -1
        self.eUTRAintegrityProtection = -1
        # reg_req
        self.mmfor = -1
        self.reg_type = -1
        self.tsc = -1
        self.nas_key_set_id = -1
        self.mcc = -1
        self.mnc = -1
        self.supi_fmt = -1
        self.type_id = -1
        # reg_accept
        self.nssaa_perf = -1
        self.sms_all = -1
        self.reg_result = -1
        self.mpsi = -1
        self.iwk_n26 = -1
        self.emf = -1
        self.emc = -1
        self.vops_n3gpp = -1
        self.vops_3gpp = -1
        self.up_ciot = -1
        self.iphc_cp_ciot = -1
        self.n3_data = -1
        self.cp_ciot = -1
        self.restrictec = -1
        self.mcsi = -1
        self.emcn3 = -1
        # reg_reject 
        self.mm_cause = -1
        # de-reg_req 
        self.switch_off = -1
        self.re_reg_req = -1
        self.acc_type = -1
        # service_req
        self.serv_type = -1
        # auth req
        self.abba = -1
        # security mode command 
        self.cipher_alg = -1
        self.integrity_alg = -1
        # pdu session estab req
        self.max_data_rate_ul = -1
        self.max_data_rate_dl = -1
        # pdu session estab accept
        self.sel_sc_mode = -1 
        self.pdu_session_type = -1
        # pdu session relea req
        self.sm_cause = -1
        # ue context relea command
        self.cause_nas = -1
        # config update command
        self.timezone = -1
    
    def to_dict(self):
        flow = {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ran_ngap_ue_id": self.ran_ngap_ue_id,
            "label": self.label,
            
            # Time Sequence Feature
            "timestamp_seq": self.timestamp_seq,
            "direc_seq": self.direc_seq,
            "procedurecode_seq": self.procedurecode_seq,
            "ngap_type_seq": self.ngap_type_seq,
            "nas_sec_seq": self.nas_sec_seq,
            "nas_type_seq": self.nas_type_seq,
            "cell_id_seq": self.cell_id_seq,
            "tac_seq": self.tac_seq,
            "time_seq": self.time_seq,
            "seq_no": self.seq_no,

            # IE Parameter Feature
            "ue_status": self.ue_status,
            "establish_cause": self.establish_cause,
            "nRencryption": self.nRencryption,
            "nRintegrityProtection": self.nRintegrityProtection,
            "eUTRAencryption": self.eUTRAencryption,
            "eUTRAintegrityProtection": self.eUTRAintegrityProtection,
            "mmfor": self.mmfor,
            "reg_type": self.reg_type,
            "tsc": self.tsc,
            "nas_key_set_id": self.nas_key_set_id,
            "mcc": self.mcc,
            "mnc": self.mnc,
            "supi_fmt": self.supi_fmt,
            "type_id": self.type_id,
            "nssaa_perf": self.nssaa_perf,
            "sms_all": self.sms_all,
            "reg_result": self.reg_result,
            "mpsi": self.mpsi,
            "iwk_n26": self.iwk_n26,
            "emf": self.emf,
            "emc": self.emc,
            "vops_n3gpp": self.vops_n3gpp,
            "vops_3gpp": self.vops_3gpp,
            "up_ciot": self.up_ciot,
            "iphc_cp_ciot": self.iphc_cp_ciot,
            "n3_data": self.n3_data,
            "cp_ciot": self.cp_ciot,
            "restrictec": self.restrictec,
            "mcsi": self.mcsi,
            "emcn3": self.emcn3,
            "mm_cause": self.mm_cause,
            "switch_off": self.switch_off,
            "re_reg_req": self.re_reg_req,
            "acc_type": self.acc_type,
            "serv_type": self.serv_type,
            "abba": self.abba,
            "cipher_alg": self.cipher_alg,
            "integrity_alg": self.integrity_alg,
            "max_data_rate_ul": self.max_data_rate_ul,
            "max_data_rate_dl": self.max_data_rate_dl,
            "sel_sc_mode": self.sel_sc_mode,
            "pdu_session_type": self.pdu_session_type,
            "sm_cause": self.sm_cause,
            "cause_nas": self.cause_nas,
            "timezone": self.timezone,
        }

        return flow
    
    def padding_cut_for_seq(self, length):
        ts_seq = self._adjust_list_length(self.timestamp_seq, length)
        new_seq = []
        init = ts_seq[0]
        for timestamp in ts_seq:
            if timestamp == -1:
                new_seq.append(0)
            else:
                new_seq.append(timestamp - init)
        self.timestamp_seq = new_seq

        t_seq = self._adjust_list_length(self.time_seq, length)
        new_seq = []
        init = t_seq[0]
        for time in t_seq:
            if time == -1:
                new_seq.append(0)
            else:
                new_seq.append(time - init)
        self.time_seq = new_seq

        self.direc_seq = self._adjust_list_length(self.direc_seq, length)
        self.procedurecode_seq = self._adjust_list_length(self.procedurecode_seq, length)
        self.ngap_type_seq = self._adjust_list_length(self.ngap_type_seq, length)
        self.nas_sec_seq = self._adjust_list_length(self.nas_sec_seq, length)
        nas_seq = self._adjust_list_length(self.nas_type_seq, length)
        new_seq = []
        for msg in nas_seq:
            if msg == -1:
                new_seq.append(-1)
            else:
                new_seq.append(msg - 65)
        self.nas_type_seq = new_seq
        self.cell_id_seq = self._adjust_list_length(self.cell_id_seq, length)
        self.tac_seq = self._adjust_list_length(self.tac_seq, length)
        self.seq_no = self._adjust_list_length(self.seq_no, length)

    def _adjust_list_length(self, seq, length):
        new_seq = []
        if len(seq) >= length:
            new_seq = seq[:length]
        else:
            new_seq = seq + [-1] * (length - len(seq))
        
        return new_seq

class NGAPConstant:
    # Max Length for Seq
    SEQ_MAX_LENgth = SEQ_MAX_LEN

    # Signaling Direction
    id_Uplink = 1
    id_Downlink = 0

    # UE State
    ID_DEREGISTERED = 0
    ID_REGISTERED_INITIATED = 1
    ID_REGISTERED = 2

    # NGAP Elementary Procedures Class 1
    id_InitiatingMessage = 0
    id_SuccessfulOutcome = 1
    id_UnsuccessfulOutcome = 2

    # NGAP Elementary Procedures Class 2
    id_AMFConfigurationUpdate                   = 0
    id_AMFStatusIndication                      = 1
    id_CellTrafficTrace                         = 2
    id_DeactivateTrace                          = 3
    id_DownlinkNASTransport                     = 4
    id_DownlinkNonUEAssociatedNRPPaTransport    = 5
    id_DownlinkRANConfigurationTransfer         = 6
    id_DownlinkRANStatusTransfer                = 7
    id_DownlinkUEAssociatedNRPPaTransport		= 8
    id_ErrorIndication							= 9
    id_HandoverCancel							= 10
    id_HandoverNotification						= 11
    id_HandoverPreparation						= 12
    id_HandoverResourceAllocation				= 13
    id_InitialContextSetup						= 14
    id_InitialUEMessage							= 15
    id_LocationReportingControl					= 16
    id_LocationReportingFailureIndication		= 17
    id_LocationReport							= 18
    id_NASNonDeliveryIndication					= 19
    id_NGReset									= 20
    id_NGSetup									= 21
    id_OverloadStart							= 22
    id_OverloadStop								= 23
    id_Paging									= 24
    id_PathSwitchRequest						= 25
    id_PDUSessionResourceModify					= 26
    id_PDUSessionResourceModifyIndication		= 27
    id_PDUSessionResourceRelease				= 28
    id_PDUSessionResourceSetup					= 29
    id_PDUSessionResourceNotify					= 30
    id_PrivateMessage							= 31
    id_PWSCancel								= 32
    id_PWSFailureIndication						= 33
    id_PWSRestartIndication						= 34
    id_RANConfigurationUpdate					= 35
    id_RerouteNASRequest						= 36
    id_RRCInactiveTransitionReport				= 37
    id_TraceFailureIndication					= 38
    id_TraceStart								= 39
    id_UEContextModification					= 40
    id_UEContextRelease							= 41
    id_UEContextReleaseRequest					= 42
    id_UERadioCapabilityCheck					= 43
    id_UERadioCapabilityInfoIndication			= 44
    id_UETNLABindingRelease						= 45
    id_UplinkNASTransport						= 46
    id_UplinkNonUEAssociatedNRPPaTransport		= 47
    id_UplinkRANConfigurationTransfer			= 48
    id_UplinkRANStatusTransfer					= 49
    id_UplinkUEAssociatedNRPPaTransport			= 50
    id_WriteReplaceWarning						= 51
    id_SecondaryRATDataUsageReport				= 52
    id_UplinkRIMInformationTransfer				= 53
    id_DownlinkRIMInformationTransfer			= 54
    id_RetrieveUEInformation					= 55
    id_UEInformationTransfer					= 56
    id_RANCPRelocationIndication				= 57
    id_UEContextResume							= 58
    id_UEContextSuspend							= 59
    id_UERadioCapabilityIDMapping				= 60
    id_HandoverSuccess							= 61
    id_UplinkRANEarlyStatusTransfer				= 62
    id_DownlinkRANEarlyStatusTransfer			= 63
    id_AMFCPRelocationIndication				= 64
    id_ConnectionEstablishmentIndication		= 65
    id_BroadcastSessionModification				= 66
    id_BroadcastSessionRelease					= 67
    id_BroadcastSessionSetup					= 68
    id_DistributionSetup 						= 69
    id_DistributionRelease 						= 70
    id_MulticastSessionActivation 				= 71
    id_MulticastSessionDeactivation 			= 72
    id_MulticastSessionUpdate 					= 73
    id_MulticastGroupPaging						= 74
    id_BroadcastSessionReleaseRequired			= 75
    id_TimingSynchronisationStatus				= 76
    id_TimingSynchronisationStatusReport		= 77
    id_MTCommunicationHandling					= 78
    id_RANPagingRequest							= 79
    id_BroadcastSessionTransport				= 80

    # NGAP Message type
    id_InitialContextSetupFailure = 81
    id_InitialContextSetupRequest = 82
    id_InitialContextSetupResponse = 83
    id_PDUSessionResourceSetupRequest = 84
    id_PDUSessionResourceSetupResponse = 85
    id_UEContextReleaseCommand = 86
    id_UEContextReleaseComplete = 87

    # NAS Security Type
    id_PlainNASMessage = 0
    id_Integrityprotected = 1
    id_IntegrityProtectedAndCiphered = 2
    id_IntegrityProtectedWithNewEPSSecurityContext = 3
    id_IntegrityProtectedAndCipheredWithNewEPSSecurityContext = 4
    id_Reserved = 5
    
    # NAS Message Type
    id_registration_request                    = 0x41
    id_registration_accept                     = 0x42
    id_registration_complete                   = 0x43
    id_registration_reject                     = 0x44
    id_deregistration_request_ue_originating   = 0x45
    id_deregistration_accept_ue_originating    = 0x46
    id_deregistration_request_ue_terminated    = 0x47
    id_deregistration_accept_ue_terminated     = 0x48
    id_not_use_in_current_version              = 0x4a
    id_service_request                         = 0x4c
    id_service_reject                          = 0x4d
    id_service_accept                          = 0x4e
    id_configuration_update_command            = 0x54
    id_configuration_update_complete           = 0x55
    id_authentication_request                  = 0x56
    id_authentication_response                 = 0x57
    id_authentication_reject                   = 0x58
    id_authentication_failure                  = 0x59
    id_authentication_result                   = 0x5a
    id_identity_request                        = 0x5b
    id_identity_response                       = 0x5c
    id_security_mode_command                   = 0x5d
    id_security_mode_complete                  = 0x5e
    id_security_mode_reject                    = 0x5f
    id_status_5gmm                             = 0x64
    id_notification                            = 0x65
    id_notification_response                   = 0x66
    id_ul_nas_transport                        = 0x67
    id_dl_nas_transport                        = 0x68
    id_pdu_session_establishment_request       = 0xc1
    id_pdu_session_establishment_accept        = 0xc2
    id_pdu_session_establishment_reject        = 0xc3
    id_pdu_session_authentication_command      = 0xc5
    id_pdu_session_authentication_complete     = 0xc6
    id_pdu_session_authentication_result       = 0xc7
    id_pdu_session_modification_request        = 0xc9
    id_pdu_session_modification_reject         = 0xca
    id_pdu_session_modification_command        = 0xcb
    id_pdu_session_modification_complete       = 0xcc
    id_pdu_session_modification_command_reject = 0xcd
    id_pdu_session_release_request             = 0xd1
    id_pdu_session_release_reject              = 0xd2
    id_pdu_session_release_command             = 0xd3
    id_pdu_session_release_complete            = 0xd4
    id_status_5gsm                             = 0xd6
    id_nulltype                                = 0xff
