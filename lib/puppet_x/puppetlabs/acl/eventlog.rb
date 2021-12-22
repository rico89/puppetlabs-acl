require 'puppet/util/windows/security'
require 'ffi'

module PuppetX
  module Puppetlabs
    module Acl
      module Eventlog
        include Puppet::Util::Windows::Security

        extend PuppetX::Puppetlabs::Acl::Eventlog
        extend FFI::Library

        typedef :pointer, :lpbool
        typedef :pointer, :pacl

        DEFAULT_ENCODING = Encoding.default_internal || Encoding.default_external
        ERROR_INSUFFICIENT_BUFFER = 0x7A
        ERROR_NO_MORE_ITEMS = 0x103
        NULL_HANDLE = 0x00

        def list_event_logs
          return @event_logs unless @event_logs.nil?

          @event_logs = []
          handle = EvtOpenChannelEnum(NULL_HANDLE, 0)

          if handle == NULL_HANDLE
            raise Puppet::Util::Windows::Error.new(_("Failed to get handle to EvtOpenChannelEnum: #{FFI::LastError.error}"))
          end

          completed = false
          loop do
            FFI::MemoryPointer.new(:uint32) do |dw_buffer_used|
              if EvtNextChannelPath(handle, 0, nil, dw_buffer_used) == FFI::WIN32_FALSE
                status = FFI::LastError.error
                if status == ERROR_NO_MORE_ITEMS
                  completed = true
                elsif status == ERROR_INSUFFICIENT_BUFFER
                  dw_buffer_size = dw_buffer_used.read_ulong * 2
                  FFI::MemoryPointer.new(dw_buffer_size) do |p_buffer|
                    if EvtNextChannelPath(handle, dw_buffer_size, p_buffer, dw_buffer_used) == FFI::WIN32_FALSE
                      raise Puppet::Util::Windows::Error.new(_("Failed to get next eventlog: #{FFI::LastError.error}"))
                    end
                    log_name = pBuffer.read_bytes(dw_buffer_size)[0...-2].force_encoding('utf-16le').encode(DEFAULT_ENCODING)
                    @event_logs.push(log_name)
                  end
                end
              end
            end
            break if completed
          end

          # close handle
          if EvtClose(handle) == FFI::WIN32_FALSE
            raise Puppet::Util::Windows::Error.new(_('Failed to close event_log handle'))
          end
          @event_logs
        end

        def exist?(event_log)
          list_event_logs.map(&:downcase).include?(event_log.downcase)
        end

        def get_sddl(event_log)
          sddl = nil
          handle = EvtOpenChannelConfig(0, wide_string(event_log), 0)
          dw_buffer_size = 0
          with_privilege(SE_BACKUP_NAME) do
            FFI::MemoryPointer.new(:uint32) do |dw_buffer_used|
              rv = EvtGetChannelConfigProperty(
                handle,
                EVT_CHANNEL_CONFIG_PROPERTY_ID[:EvtChannelConfigAccess],
                0,
                dw_buffer_size,
                FFI::Pointer::NULL,
                dw_buffer_used,
              )

              status = FFI::LastError.error
              unless status == ERROR_INSUFFICIENT_BUFFER
                raise Puppet::Util::Windows::Error.new(_('Failed to get security information')) if rv == FFI::WIN32_FALSE
              end

              dw_buffer_size = dw_buffer_used.read_ulong
              FFI::MemoryPointer.new(:byte, dw_buffer_size) do |property_ptr|
                rv = EvtGetChannelConfigProperty(
                  handle,
                  EVT_CHANNEL_CONFIG_PROPERTY_ID[:EvtChannelConfigAccess],
                  0,
                  dw_buffer_size,
                  property_ptr,
                  dw_buffer_used,
                )
                raise Puppet::Util::Windows::Error.new(_('Failed to get security information')) if rv == FFI::WIN32_FALSE
                data = property_ptr.read_string(dw_buffer_size)
                sddl = data[16...-2].force_encoding('utf-16le').encode(DEFAULT_ENCODING)
              end
            end

            # close handle
            if EvtClose(handle) == FFI::WIN32_FALSE
              raise Puppet::Util::Windows::Error.new(_('Failed to close event_log handle'))
            end
          end
          sddl
        end

        def get_owner_from_sd_ptr(sd_ptr)
          owner = nil
          FFI::MemoryPointer.new(:pointer) do |sid_ptr_ptr|
            FFI::MemoryPointer.new(:win32_bool) do |bool_ptr|
              if GetSecurityDescriptorOwner(sd_ptr, sid_ptr_ptr, bool_ptr) == FFI::WIN32_FALSE
                raise Puppet::Util::Windows::Error.new(_("GetSecurityDescriptorOwner failed. error: #{FFI::LastError.error}"))
              end
              sid_ptr = sid_ptr_ptr.get_pointer(0)
              owner = Puppet::Util::Windows::SID.sid_ptr_to_string(sid_ptr)
            end
          end
          owner
        end

        def get_group_from_sd_ptr(sd_ptr)
          group = nil
          FFI::MemoryPointer.new(:pointer) do |sid_ptr_ptr|
            FFI::MemoryPointer.new(:win32_bool) do |bool_ptr|
              if GetSecurityDescriptorGroup(sd_ptr, sid_ptr_ptr, bool_ptr) == FFI::WIN32_FALSE
                raise Puppet::Util::Windows::Error.new(_("GetSecurityDescriptorGroup failed. error: #{FFI::LastError.error}"))
              end
              sid_ptr = sid_ptr_ptr.get_pointer(0)
              group = Puppet::Util::Windows::SID.sid_ptr_to_string(sid_ptr)
            end
          end
          group
        end

        def get_dacl_from_sd_ptr(sd_ptr)
          dacl = nil
          FFI::MemoryPointer.new(:win32_bool) do |lpb_dacl_present|
            FFI::MemoryPointer.new(:pointer) do |dacl_ptr_ptr|
              FFI::MemoryPointer.new(:win32_bool) do |lpb_dacl_defaulted|
                if GetSecurityDescriptorDacl(sd_ptr, lpb_dacl_present, dacl_ptr_ptr, lpb_dacl_defaulted) == FFI::WIN32_FALSE
                  raise "GetSecurityDescriptorDacl failed. error: #{FFI::LastError.error}"
                end
                dacl_ptr = dacl_ptr_ptr.get_pointer(0)
                dacl = Puppet::Util::Windows::Security.parse_dacl(dacl_ptr)
              end
            end
          end
          dacl
        end

        def get_protect_from_sd_ptr(sd_ptr)
          protect = true
          FFI::MemoryPointer.new(:word, 1) do |control|
            FFI::MemoryPointer.new(:dword, 1) do |revision|
              if GetSecurityDescriptorControl(sd_ptr, control, revision) == FFI::WIN32_FALSE
                raise Puppet::Util::Windows::Error.new(_("Failed to get sd control: #{FFI::LastError.error}"))
              end
              protect = (control.read_word & SE_DACL_PROTECTED) == SE_DACL_PROTECTED
            end
          end
          protect
        end

        def get_security_descriptor(event_log)
          sd = nil

          sddl = get_sddl(event_log)

          FFI::MemoryPointer.new(:pointer, 1) do |sd_ptr_ptr|
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide_string(sddl), 1, sd_ptr_ptr, FFI::Pointer::NULL) == FFI::WIN32_FALSE
              raise Puppet::Util::Windows::Error.new(_("Failed to convert sddl to sd: #{FFI::LastError.error}"))
            end

            sd_ptr_ptr.read_win32_local_pointer do |sd_ptr|
              owner = get_owner_from_sd_ptr(sd_ptr)
              group = get_group_from_sd_ptr(sd_ptr)
              dacl = get_dacl_from_sd_ptr(sd_ptr)
              protect = get_protect_from_sd_ptr(sd_ptr)

              sd = Puppet::Util::Windows::SecurityDescriptor.new(owner, group, dacl, protect)
            end
          end
          sd
        end

        def set_owner_to_sd_ptr(sd_ptr, owner)
          Puppet::Util::Windows::SID.string_to_sid_ptr(owner) do |sid_ptr|
            if SetSecurityDescriptorOwner(sd_ptr, sid_ptr, false) == FFI::WIN32_FALSE
              raise Puppet::Util::Windows::Error.new(_("Failed to set SecurityDescriptor Owner: #{FFI::LastError.error}"))
            end
          end
          nil
        end

        def set_group_to_sd_ptr(sd_ptr, group)
          Puppet::Util::Windows::SID.string_to_sid_ptr(group) do |sid_ptr|
            if SetSecurityDescriptorGroup(sd_ptr, sid_ptr, false) == FFI::WIN32_FALSE
              raise Puppet::Util::Windows::Error.new(_("Failed to set SecurityDescriptor Group: #{FFI::LastError.error}"))
            end
          end
          nil
        end

        def set_dacl_to_sd_ptr(sd_ptr, dacl)
          FFI::MemoryPointer.new(:byte, get_max_generic_acl_size(dacl.count)) do |acl_ptr|
            if InitializeAcl(acl_ptr, acl_ptr.size, ACL_REVISION) == FFI::WIN32_FALSE
              raise Puppet::Util::Windows::Error.new(_('Failed to initialize ACL'))
            end

            if IsValidAcl(acl_ptr) == FFI::WIN32_FALSE
              raise Puppet::Util::Windows::Error.new(_('Invalid DACL'))
            end
            dacl.each do |ace|
              case ace.type
              when Puppet::Util::Windows::AccessControlEntry::ACCESS_ALLOWED_ACE_TYPE
                add_access_allowed_ace(acl_ptr, ace.mask, ace.sid, ace.flags)
              when Puppet::Util::Windows::AccessControlEntry::ACCESS_DENIED_ACE_TYPE
                add_access_denied_ace(acl_ptr, ace.mask, ace.sid, ace.flags)
              else
                raise 'We should never get here'
              end
            end
            if SetSecurityDescriptorDacl(sd_ptr, true, acl_ptr, false) == FFI::WIN32_FALSE
              raise Puppet::Util::Windows::Error.new(_("Failed to set dacl to SecurityDescriptor: #{FFI::LastError.error}"))
            end
          end
          nil
        end

        def set_security_descriptor(event_log, sd)
          FFI::MemoryPointer.new(20) do |sd_ptr|
            if InitializeSecurityDescriptor(sd_ptr, 1) == FFI::WIN32_FALSE
              raise Puppet::Util::Windows::Error.new(_("Failed to initialize SecurityDescriptor: #{FFI::LastError.error}"))
            end

            set_owner_to_sd_ptr(sd_ptr, sd.owner)
            set_group_to_sd_ptr(sd_ptr, sd.group)
            set_dacl_to_sd_ptr(sd_ptr, sd.dacl)

            # protected means the object does not inherit aces from its parent
            flags = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
            flags |= sd.protect ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION

            FFI::MemoryPointer.new(:pointer) do |sddl_ptr_ptr|
              FFI::MemoryPointer.new(:ulong) do |sddl_len_ptr|
                if ConvertSecurityDescriptorToStringSecurityDescriptorW(sd_ptr, 1, flags, sddl_ptr_ptr, sddl_len_ptr) == FFI::WIN32_FALSE
                  raise Puppet::Util::Windows::Error.new(_("Failed to convert sd to sddl: #{FFI::LastError.error}"))
                end
                set_sddl(event_log, sddl_ptr_ptr.get_pointer(0))
              end
            end
          end
          nil
        end

        def set_sddl(log, sddl_ptr)
          with_privilege(SE_BACKUP_NAME) do
            with_privilege(SE_RESTORE_NAME) do
              handle = EvtOpenChannelConfig(0, wide_string(log), 0)
              if handle == 0
                raise 'could not open handle to event_log'
              end
              data = EvtVariant.new
              data[:Type] = EVT_VARIANT_TYPE[:EvtVarTypeString]
              data[:StringVal] = sddl_ptr
              rv = EvtSetChannelConfigProperty(
                handle,
                EVT_CHANNEL_CONFIG_PROPERTY_ID[:EvtChannelConfigAccess],
                0,
                data.pointer,
              )
              raise Puppet::Util::Windows::Error.new(_("Failed to set eventlog config property: #{FFI::LastError.error}")) if rv == FFI::WIN32_FALSE

              # sace eventlog config
              if EvtSaveChannelConfig(handle, 0) == FFI::WIN32_FALSE
                raise Puppet::Util::Windows::Error.new(_("Failed to save eventlog config property: #{FFI::LastError.error}"))
              end

              # close eventlog handle
              if EvtClose(handle) == FFI::WIN32_FALSE
                raise Puppet::Util::Windows::Error.new(_('Failed to close event_log handle'))
              end
            end
          end
        end

        # https://docs.microsoft.com/en-us/windows/win32/api/winevt/ns-winevt-evt_variant
        # TODO: what does union in c# do and how to translate it propertly to ruby
        class EvtVariant < FFI::Struct
          layout(
            #:EVT_Property, EVT_Property,
            #:ByteVal, :uint8,
            :StringVal, :pointer,
            :Count, :dword,
            :Type, :dword
          )
        end

        # https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_descriptor
        # typedef struct _SECURITY_DESCRIPTOR {
        #   BYTE                        Revision;
        #   BYTE                        Sbz1;
        #   SECURITY_DESCRIPTOR_CONTROL Control;
        #   PSID                        Owner;
        #   PSID                        Group;
        #   PACL                        Sacl;
        #   PACL                        Dacl;
        # } SECURITY_DESCRIPTOR, *PISECURITY_DESCRIPTOR;
        class SecurityDescriptor < FFI::Struct
          layout(
            :Revision, :byte,
            :Sbz1,     :byte,
            :Control,  :word, # https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control
            :Owner,    :psid,
            :Group,    :psid,
            :Sacl,     :pacl,
            :Dacl,     :pacl
          )
        end

        # https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_variant_type
        EVT_VARIANT_TYPE = enum(
          :EvtVarTypeNull, 0,
          :EvtVarTypeString,
          :EvtVarTypeAnsiString,
          :EvtVarTypeSByte,
          :EvtVarTypeByte,
          :EvtVarTypeInt16,
          :EvtVarTypeUInt16,
          :EvtVarTypeInt32,
          :EvtVarTypeUInt32,
          :EvtVarTypeInt64,
          :EvtVarTypeUInt64,
          :EvtVarTypeSingle,
          :EvtVarTypeDouble,
          :EvtVarTypeBoolean,
          :EvtVarTypeBinary,
          :EvtVarTypeGuid,
          :EvtVarTypeSizeT,
          :EvtVarTypeFileTime,
          :EvtVarTypeSysTime,
          :EvtVarTypeSid,
          :EvtVarTypeHexInt32,
          :EvtVarTypeHexInt64,
          :EvtVarTypeEvtHandle,
          :EvtVarTypeEvtXml
        )

        # https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_channel_config_property_id
        EVT_CHANNEL_CONFIG_PROPERTY_ID = enum(
          :EvtChannelConfigEnabled, 0,
          :EvtChannelConfigIsolation,
          :EvtChannelConfigType,
          :EvtChannelConfigOwningPublisher,
          :EvtChannelConfigClassicEventlog,
          :EvtChannelConfigAccess,
          :EvtChannelLoggingConfigRetention,
          :EvtChannelLoggingConfigAutoBackup,
          :EvtChannelLoggingConfigMaxSize,
          :EvtChannelLoggingConfigLogFilePath,
          :EvtChannelPublishingConfigLevel,
          :EvtChannelPublishingConfigKeywords,
          :EvtChannelPublishingConfigControlGuid,
          :EvtChannelPublishingConfigBufferSize,
          :EvtChannelPublishingConfigMinBuffers,
          :EvtChannelPublishingConfigMaxBuffers,
          :EvtChannelPublishingConfigLatency,
          :EvtChannelPublishingConfigClockType,
          :EvtChannelPublishingConfigSidType,
          :EvtChannelPublisherList,
          :EvtChannelPublishingConfigFileMax,
          :EvtChannelConfigPropertyIdEND
        )

        # https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtopenchannelenum
        # HANDLE EVT_HANDLE EvtOpenChannelEnum(
        #   _In_       EVT_HANDLE Session,
        #   _In_       DWORD      Flags
        # );
        ffi_lib :wevtapi
        attach_function :EvtOpenChannelEnum,
          [:handle, :dword], :handle

        # https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnextchannelpath
        # BOOL EvtNextChannelPath(
        #   _In_       EVT_HANDLE ChannelEnum,
        #   _In_       DWORD      ChannelPathBufferSize,
        #   _In_       LPWSTR     ChannelPathBuffer,
        #   _out_      PDWORD     ChannelPathBufferUsed
        # );
        ffi_lib :wevtapi
        attach_function :EvtNextChannelPath,
          [:handle, :dword, :lpwstr, :pdword], :win32_bool

        # https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtopenchannelconfig
        # EVT_HANDLE EvtOpenChannelConfig(
        #   [in] EVT_HANDLE Session,
        #   [in] LPCWSTR    ChannelPath,
        #   [in] DWORD      Flags
        # );
        ffi_lib :wevtapi
        attach_function_private :EvtOpenChannelConfig,
          [:handle, :lpcwstr, :dword], :handle

        # BOOL EvtGetChannelConfigProperty(
        #   [in]  EVT_HANDLE                     ChannelConfig,
        #   [in]  EVT_CHANNEL_CONFIG_PROPERTY_ID PropertyId,
        #   [in]  DWORD                          Flags,
        #   [in]  DWORD                          PropertyValueBufferSize,
        #   [in]  PEVT_VARIANT                   PropertyValueBuffer,
        #   [out] PDWORD                         PropertyValueBufferUsed
        # );
        ffi_lib :wevtapi
        attach_function_private :EvtGetChannelConfigProperty,
          [:handle, :dword, :dword, :dword, :pointer, :pdword], :win32_bool

        # https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsetchannelconfigproperty
        # BOOL EvtSetChannelConfigProperty(
        #   [in]  EVT_HANDLE                     ChannelConfig,
        #   [in]  EVT_CHANNEL_CONFIG_PROPERTY_ID PropertyId,
        #   [in]  DWORD                          Flags,
        #   [in]  PEVT_VARIANT                   PropertyValueBuffer
        # );
        ffi_lib :wevtapi
        attach_function_private :EvtSetChannelConfigProperty,
          [:handle, :dword, :dword, :pointer], :win32_bool

        # https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsavechannelconfig
        # BOOL EvtSaveChannelConfig(
        #   [in] EVT_HANDLE ChannelConfig,
        #   [in] DWORD      Flags
        # );
        ffi_lib :wevtapi
        attach_function_private :EvtSaveChannelConfig,
          [:handle, :dword], :win32_bool

        # https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtclose
        # BOOL EvtClose(
        #   [in] EVT_HANDLE Object
        # );
        ffi_lib :wevtapi
        attach_function_private :EvtClose,
          [:handle], :win32_bool

        # https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptorw
        # BOOL ConvertStringSecurityDescriptorToSecurityDescriptorW(
        #   [in]  LPCWSTR              StringSecurityDescriptor,
        #   [in]  DWORD                StringSDRevision,
        #   [out] PSECURITY_DESCRIPTOR *SecurityDescriptor,
        #   [out] PULONG               SecurityDescriptorSize
        # );
        ffi_lib :advapi32
        attach_function_private :ConvertStringSecurityDescriptorToSecurityDescriptorW,
          [:lpcwstr, :dword, :pointer, :pulong], :win32_bool

        # https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsecuritydescriptortostringsecuritydescriptorw
        # BOOL ConvertSecurityDescriptorToStringSecurityDescriptorW(
        #   [in]  PSECURITY_DESCRIPTOR SecurityDescriptor,
        #   [in]  DWORD                RequestedStringSDRevision,
        #   [in]  SECURITY_INFORMATION SecurityInformation,
        #   [out] LPWSTR               *StringSecurityDescriptor,
        #   [out] PULONG               StringSecurityDescriptorLen
        # );
        ffi_lib :advapi32
        attach_function_private :ConvertSecurityDescriptorToStringSecurityDescriptorW,
          [:pointer, :dword, :dword, :lpwstr, :pulong], :win32_bool

        # https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsecuritydescriptorowner
        # BOOL GetSecurityDescriptorOwner(
        #   [in]  PSECURITY_DESCRIPTOR pSecurityDescriptor,
        #   [out] PSID                 *pOwner,
        #   [out] LPBOOL               lpbOwnerDefaulted
        # );
        ffi_lib :advapi32
        attach_function_private :GetSecurityDescriptorOwner,
          [:pointer, :psid, :lpbool], :win32_bool

        # https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsecuritydescriptorgroup
        # BOOL GetSecurityDescriptorGroup(
        #   [in]  PSECURITY_DESCRIPTOR pSecurityDescriptor,
        #   [out] PSID                 *pOwner,
        #   [out] LPBOOL               lpbOwnerDefaulted
        # );
        ffi_lib :advapi32
        attach_function_private :GetSecurityDescriptorGroup,
          [:pointer, :psid, :lpbool], :win32_bool

        # https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsecuritydescriptordacl
        # BOOL GetSecurityDescriptorDacl(
        #   [in]  PSECURITY_DESCRIPTOR pSecurityDescriptor,
        #   [out] LPBOOL               lpbDaclPresent,
        #   [out] PACL                 *pDacl,
        #   [out] LPBOOL               lpbDaclDefaulted
        # );
        ffi_lib :advapi32
        attach_function_private :GetSecurityDescriptorDacl,
          [:pointer, :lpbool, :psid, :lpbool], :win32_bool

        # https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsecuritydescriptorsacl
        # BOOL GetSecurityDescriptorSacl(
        #   [in]  PSECURITY_DESCRIPTOR pSecurityDescriptor,
        #   [out] LPBOOL               lpbDaclPresent,
        #   [out] PACL                 *pDacl,
        #   [out] LPBOOL               lpbDaclDefaulted
        # );
        ffi_lib :advapi32
        attach_function_private :GetSecurityDescriptorSacl,
          [:pointer, :lpbool, :psid, :lpbool], :win32_bool

        # https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-initializesecuritydescriptor
        # BOOL InitializeSecurityDescriptor(
        #   [out] PSECURITY_DESCRIPTOR pSecurityDescriptor,
        #   [in]  DWORD                dwRevision
        # );
        ffi_lib :advapi32
        attach_function_private :InitializeSecurityDescriptor,
          [:pointer, :dword], :win32_bool

        # https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-setsecuritydescriptorowner
        # BOOL SetSecurityDescriptorOwner(
        #   [in, out]      PSECURITY_DESCRIPTOR pSecurityDescriptor,
        #   [in, optional] PSID                 pOwner,
        #   [in]           BOOL                 bOwnerDefaulted
        # );
        ffi_lib :advapi32
        attach_function_private :SetSecurityDescriptorOwner,
          [:pointer, :psid, :bool], :win32_bool

        # https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-setsecuritydescriptorgroup
        # BOOL SetSecurityDescriptorGroup(
        #   [in, out]      PSECURITY_DESCRIPTOR pSecurityDescriptor,
        #   [in, optional] PSID                 pGroup,
        #   [in]           BOOL                 bGroupDefaulted
        # );
        ffi_lib :advapi32
        attach_function_private :SetSecurityDescriptorGroup,
          [:pointer, :psid, :bool], :win32_bool

        # BOOL SetSecurityDescriptorDacl(
        #   [in, out]      PSECURITY_DESCRIPTOR pSecurityDescriptor,
        #   [in]           BOOL                 bDaclPresent,
        #   [in, optional] PACL                 pDacl,
        #   [in]           BOOL                 bDaclDefaulted
        # );
        ffi_lib :advapi32
        attach_function_private :SetSecurityDescriptorDacl,
          [:pointer, :bool, :pacl, :bool], :win32_bool
      end
    end
  end
end
