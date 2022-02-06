# Nordic  BLE DFU Bootloader

## Overview

Two devices are involved when performing a Device Firmware Update (DFU). The DFU controller is the device that transfers the image. For instance, the DFU controller can be an app on a mobile phone. The DFU target device will be updated with a new firmware image, which can contain a new application, SoftDevice, bootloader, or a combination of SoftDevice and bootloader. 

Containing a bootloader with DFU capabilities, bootloader takes the responsibility to start either the application or the DFU mode. The DFU module is part of the bootloader. If DFU mode is started successfully, the DFU controller will initiate the transfer of a firmware image. The firmware image will then be validated by the bootloader and will replace the existing firmware if it passes the validation. 
![bootloader](https://user-images.githubusercontent.com/25619082/152700139-18ef0c56-b8f8-4cc9-a840-228e0277b9e3.jpg)



## Start Application from Bootloader
Bootloader will start either the application or the DFU mode, depending on different triggers. By default, the DFU bootloader will start the application that is located at a **specific place in memory**. According to the code in [nrf_bootloader_app_start.c](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/libraries/bootloader/nrf_bootloader_app_start.c), bootloader always boots from end of MRB (`uint32_t start_addr = MBR_SIZE`). The size of MBR is `0x1000` (Defined in [nrf_mrb.h](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/softdevice/s140/headers/nrf52/nrf_mbr.h))
```c
void nrf_bootloader_app_start(void)
{
    uint32_t start_addr = MBR_SIZE; // Always boot from end of MBR. If a SoftDevice is present, it will boot the app.
    NRF_LOG_DEBUG("Running nrf_bootloader_app_start with address: 0x%08x", start_addr);
    uint32_t err_code;
    // Disable and clear interrupts
    // Notice that this disables only 'external' interrupts (positive IRQn).
    NRF_LOG_DEBUG("Disabling interrupts. NVIC->ICER[0]: 0x%x", NVIC->ICER[0]);

    NVIC->ICER[0]=0xFFFFFFFF;
    NVIC->ICPR[0]=0xFFFFFFFF;
    #if defined(__NRF_NVIC_ISER_COUNT) && __NRF_NVIC_ISER_COUNT == 2
    	NVIC->ICER[1]=0xFFFFFFFF;
    	NVIC->ICPR[1]=0xFFFFFFFF;
	#endif
	err_code = nrf_dfu_mbr_irq_forward_address_set();
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Failed running nrf_dfu_mbr_irq_forward_address_set()");
    }

    NRF_LOG_FLUSH();
    nrf_bootloader_app_start_final(start_addr);
}
```


## Enter DFU Mode from Bootloader
DFU mode can be started in the following cases:

* No application is installed on the device.
* Button 4 is pressed when starting the device.
* The application on the DFU target supports entering DFU mode. In this case, the DFU controller can trigger the application to reset the device and enter DFU mode, which is referred to as buttonless update. 

The following code in [nrf_bootloader.c](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/libraries/bootloader/nrf_bootloader.c) controls whether enter DFU model or not. 
```c
// Check if an update needs to be activated and activate it.
	activation_result = nrf_bootloader_fw_activate();
	switch (activation_result)
	{
    	case ACTIVATION_NONE:
        	initial_timeout = NRF_BOOTLOADER_MS_TO_TICKS(NRF_BL_DFU_INACTIVITY_TIMEOUT_MS);
        	dfu_enter       = dfu_enter_check();
        	break;

    	case ACTIVATION_SUCCESS_EXPECT_ADDITIONAL_UPDATE:
        	initial_timeout = NRF_BOOTLOADER_MS_TO_TICKS(NRF_BL_DFU_CONTINUATION_TIMEOUT_MS);
        	dfu_enter       = true;
        	break;

        case ACTIVATION_SUCCESS:
            bootloader_reset(true);
            NRF_LOG_ERROR("Unreachable");
            return NRF_ERROR_INTERNAL; // Should not reach this.

        case ACTIVATION_ERROR:
        default:
            return NRF_ERROR_INTERNAL;
    }
```


### DFU Validation (Secure DFU)
Once entering DFU mode, the DFU controller will initiate the transfer of a firmware image, which is received and validated by the DFU target. If the image is valid, the device resets and the bootloader activates the image to replace the existing firmware. The following figure shows the required steps for a firmware update that is implemented in the DFU target:

![dft_flow](https://user-images.githubusercontent.com/25619082/152700128-073a5525-06ef-44fd-b001-ac5705e9c8c6.png)


Before a Device Firmware Update (DFU) is completed, the new image should be validated. The validations are performed before the actual firmware is transferred (***prevalidation***) and after the transfer (***postvalidation***). The provided firmware package must include the firmware image and an init packet that can be used to prevalidate the image. To be compatible, the validation and the image creation must use the same init packet format. 



##### Validation

Validation of the image includes to verify that the image originates from a trusted source and that it is compatible with the device and current firmware and hardware. The version validation can be skipped if the falg `is_debug` is enabled.  

Verification is done in the following order:

1. **Signature of the packet**, `signature`. The validation code needs the public key that corresponds to the private key that was used to sign the init packet. The key is located in the file `dfu_public_key.c`. The signature verification can be enabled/disabled with the `NRF_DFU_REQUIRE_SIGND_APP_UPDATE` config. 
2. **Firmware type**, `fw_type`. 
3. **Hardware version**, `hw_version`.
4. **SoftDevice version**, `hw_version`
5. **Firmware version**, `fw_verison`
6. **Firmware size**

If one of these verification steps fails, an error code is sent via the transport. 



###### nrf_dfu_validation_signature_check

Source code available on [nrf_dfu_validation.c](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/libraries/bootloader/dfu/nrf_dfu_validation.c)

* `signature_type`: DFU signature type
* `p_signature`: pointer to the boot validation data
* `signature_len`: size of the signature
* `p_data`: start address of the current firmware image
* `data_len`: the size of the entire firmware image

```c#
static nrf_dfu_result_t nrf_dfu_validation_signature_check(dfu_signature_type_t signature_type,
                                                           uint8_t      const * p_signature,
                                                           uint32_t             signature_len,
                                                           uint8_t      const * p_data,
                                                           uint32_t             data_len)
{
    ret_code_t err_code;
    size_t     hash_len = NRF_CRYPTO_HASH_SIZE_SHA256;
    nrf_crypto_hash_context_t         hash_context   = {0};
    nrf_crypto_ecdsa_verify_context_t verify_context = {0};
    crypto_init();
    NRF_LOG_INFO("Signature required. Checking signature.")
    if (p_signature == NULL)
    {
        NRF_LOG_WARNING("No signature found.");
        return EXT_ERR(NRF_DFU_EXT_ERROR_SIGNATURE_MISSING);
    }

    if (signature_type != DFU_SIGNATURE_TYPE_ECDSA_P256_SHA256)
    {
        NRF_LOG_INFO("Invalid signature type");
        return EXT_ERR(NRF_DFU_EXT_ERROR_WRONG_SIGNATURE_TYPE);
    }

    NRF_LOG_INFO("Calculating hash (len: %d)", data_len);
    err_code = nrf_crypto_hash_calculate(&hash_context,
                                         &g_nrf_crypto_hash_sha256_info,
                                         p_data,
                                         data_len,
                                         m_sig_hash,
                                         &hash_len);
    if (err_code != NRF_SUCCESS)
    {
        return NRF_DFU_RES_CODE_OPERATION_FAILED;
    }

    if (sizeof(m_signature) != signature_len)
    {
        return NRF_DFU_RES_CODE_OPERATION_FAILED;
    }

    // Prepare the signature received over the air.
    memcpy(m_signature, p_signature, signature_len);

    // Calculate the signature.
    NRF_LOG_INFO("Verify signature");

    // The signature is in little-endian format. Change it to big-endian format for nrf_crypto use.
    nrf_crypto_internal_double_swap_endian_in_place(m_signature, sizeof(m_signature) / 2);

    err_code = nrf_crypto_ecdsa_verify(&verify_context,
                                       &m_public_key,
                                       m_sig_hash,
                                       hash_len,
                                       m_signature,
                                       sizeof(m_signature));
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Signature failed (err_code: 0x%x)", err_code);
        NRF_LOG_DEBUG("Signature:");
        NRF_LOG_HEXDUMP_DEBUG(m_signature, sizeof(m_signature));
        NRF_LOG_DEBUG("Hash:");
        NRF_LOG_HEXDUMP_DEBUG(m_sig_hash, hash_len);
        NRF_LOG_DEBUG("Public Key:");
        NRF_LOG_HEXDUMP_DEBUG(pk, sizeof(pk));
        NRF_LOG_FLUSH();

        return NRF_DFU_RES_CODE_INVALID_OBJECT;
    }

    NRF_LOG_INFO("Image verified");
    return NRF_DFU_RES_CODE_SUCCESS;
}
```


##### Rules for versions

`dfu_handle_prevalidate` is in charge of version validation.  

* **Hardware version**: Accepted if the hardware version in init packet matches the hardware of the device
* **SoftDevice Firmware ID**: Accepted if one of the specified firmware IDs matches the ID of the current SoftDevice. 
* **Firmware version**: Accepted if the new version is greater than the existing version. 

###### nrf_dfu_prevalidate

Source code available on [nrf_dfu_validation.c](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/libraries/bootloader/dfu/nrf_dfu_validation.c)

```c#
nrf_dfu_result_t nrf_dfu_validation_prevalidate(void)
{
    nrf_dfu_result_t                 ret_val        = NRF_DFU_RES_CODE_SUCCESS;
    dfu_command_t            const * p_command      = &m_packet.command;
    dfu_signature_type_t             signature_type = DFU_SIGNATURE_TYPE_MIN;
    uint8_t                  const * p_signature    = NULL;
    uint32_t                         signature_len  = 0;
    if (m_packet.has_signed_command)
    {
        p_command      = &m_packet.signed_command.command;
        signature_type =  m_packet.signed_command.signature_type;
        p_signature    =  m_packet.signed_command.signature.bytes;
        signature_len  =  m_packet.signed_command.signature.size;
    }
    // Validate signature.
    if (signature_required(p_command->init.type))
    {
        ret_val = nrf_dfu_validation_signature_check(signature_type,
                                                     p_signature,
                                                     signature_len,
                                                     m_init_packet_data_ptr,
                                                     m_init_packet_data_len);
    }

    // Validate versions.
    if (ret_val == NRF_DFU_RES_CODE_SUCCESS)
    {
        ret_val = nrf_dfu_ver_validation_check(&p_command->init);
    }

    if (ret_val != NRF_DFU_RES_CODE_SUCCESS)
    {
        NRF_LOG_WARNING("Prevalidation failed.");
        NRF_LOG_DEBUG("Init command:");
        NRF_LOG_HEXDUMP_DEBUG(m_init_packet_data_ptr, m_init_packet_data_len);
    }

    return ret_val;
}
```


###### Legacy DFU vs Secure DFU

Secure DFU is more secure in the way that only signed and verified firmware images can be updated. If the bootloader cannot verify the image, it will not update it. However, with a legacy bootloader, all valid firmware images would be accepted and updated, exposing the device for unauthorized firmware updates. Nordic devices begin to replace Legacy DFU with Secure DFU from 2016 which is the time DFU with signing was introduced in SDK 12.0.0. 

 



#### Details in Source Code

##### Prevalidation

![prevalidation](https://user-images.githubusercontent.com/25619082/152700146-f5a2b3cb-cda3-425f-93e0-1fca59c5c421.png)



##### Postvalidation

![postvalidate](https://user-images.githubusercontent.com/25619082/152700135-53659dda-98b7-43d2-9cd6-79b0143cadc2.png)

![new_postvalidate](https://user-images.githubusercontent.com/25619082/152700297-c0bbf380-cac8-46b5-9286-24b6a4bee977.png)

###### nrf_bootloader_init

Source Code available on [bootloader.c](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/libraries/bootloader/nrf_bootloader.c)

```c
ret_code_t nrf_bootloader_init(nrf_dfu_observer_t observer)
{
    NRF_LOG_DEBUG("In nrf_bootloader_init");
    
	ret_code_t                            ret_val;
	nrf_bootloader_fw_activation_result_t activation_result;
	uint32_t                              initial_timeout;
	bool                                  dfu_enter = false;

	m_user_observer = observer;

	if (NRF_BL_DFU_ENTER_METHOD_BUTTON)
	{
    	dfu_enter_button_init();
	}

	ret_val = nrf_dfu_settings_init(false);
	if (ret_val != NRF_SUCCESS)
	{
    	return NRF_ERROR_INTERNAL;
	}

	#if NRF_BL_DFU_ALLOW_UPDATE_FROM_APP
	// Postvalidate if DFU has signaled that update is ready.
	if (s_dfu_settings.bank_current == NRF_DFU_CURRENT_BANK_1)
	{
    	postvalidate();
	}
	#endif

    // Check if an update needs to be activated and activate it.
    activation_result = nrf_bootloader_fw_activate();

    switch (activation_result)
    {
        case ACTIVATION_NONE:
            initial_timeout = NRF_BOOTLOADER_MS_TO_TICKS(NRF_BL_DFU_INACTIVITY_TIMEOUT_MS);
            dfu_enter       = dfu_enter_check();
            break;

        case ACTIVATION_SUCCESS_EXPECT_ADDITIONAL_UPDATE:
            initial_timeout = NRF_BOOTLOADER_MS_TO_TICKS(NRF_BL_DFU_CONTINUATION_TIMEOUT_MS);
            dfu_enter       = true;
            break;

        case ACTIVATION_SUCCESS:
            bootloader_reset(true);
            NRF_LOG_ERROR("Unreachable");
            return NRF_ERROR_INTERNAL; // Should not reach this.

        case ACTIVATION_ERROR:
        default:
            return NRF_ERROR_INTERNAL;
    }

    if (dfu_enter)
    {
        nrf_bootloader_wdt_init();
        scheduler_init();
        dfu_enter_flags_clear();

        // Call user-defined init function if implemented
        ret_val = nrf_dfu_init_user();
        if (ret_val != NRF_SUCCESS)
        {
            return NRF_ERROR_INTERNAL;
        }

        nrf_bootloader_dfu_inactivity_timer_restart(initial_timeout, inactivity_timeout);

        ret_val = nrf_dfu_init(dfu_observer);
        if (ret_val != NRF_SUCCESS)
        {
            return NRF_ERROR_INTERNAL;
        }

        NRF_LOG_DEBUG("Enter main loop");
        loop_forever(); // This function will never return.
        NRF_LOG_ERROR("Unreachable");
    }
    else
    {
        // Erase additional data like peer data or advertisement name
        ret_val = nrf_dfu_settings_additional_erase();
        if (ret_val != NRF_SUCCESS)
        {
            return NRF_ERROR_INTERNAL;
        }

        m_flash_write_done = false;
        nrf_dfu_settings_backup(flash_write_callback);
        ASSERT(m_flash_write_done);

        nrf_bootloader_app_start();
        NRF_LOG_ERROR("Unreachable");
    }

    // Should not be reached.
    return NRF_ERROR_INTERNAL;
}
```



###### nrf_dfu_init

Source Code available on [nrf_dfu.c](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/libraries/bootloader/dfu/nrf_dfu.c)

```c
uint32_t nrf_dfu_init(nrf_dfu_observer_t observer)
{
    uint32_t ret_val;
    
	m_user_observer = observer;

	NRF_LOG_INFO("Entering DFU mode.");

	dfu_observer(NRF_DFU_EVT_DFU_INITIALIZED);

	// Initializing transports
	ret_val = nrf_dfu_transports_init(dfu_observer);
	if (ret_val != NRF_SUCCESS)
	{
    	NRF_LOG_ERROR("Could not initalize DFU transport: 0x%08x", ret_val);
    	return ret_val;
	}

	ret_val = nrf_dfu_req_handler_init(dfu_observer);

	return ret_val;
}
```



###### nrf_duf_req_handler_init

Source code available on [nrf_duf_req_handle.c](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/libraries/bootloader/dfu/nrf_dfu_req_handler.c)

```c
ret_code_t nrf_dfu_req_handler_init(nrf_dfu_observer_t observer)
{
    ret_code_t       ret_val;
    nrf_dfu_result_t result;

    if (observer == NULL)
	{
    	return NRF_ERROR_INVALID_PARAM;
	}
#if defined(BLE_STACK_SUPPORT_REQD) || defined(ANT_STACK_SUPPORT_REQD)
    ret_val  = nrf_dfu_flash_init(true);
#else
    ret_val = nrf_dfu_flash_init(false);
#endif
    if (ret_val != NRF_SUCCESS)
    {
        return ret_val;
    }
	nrf_dfu_validation_init();
	if (nrf_dfu_validation_init_cmd_present())
	{
    	/* Execute a previously received init packed. Subsequent executes will have no 	effect. */
    	result = nrf_dfu_validation_init_cmd_execute(&m_firmware_start_addr, &m_firmware_size_req);
    	if (result != NRF_DFU_RES_CODE_SUCCESS)
    	{
        	/* Init packet in flash is not valid! */
        	return NRF_ERROR_INTERNAL;
    	}
	}
	
	m_observer = observer;

	/* Initialize extended error handling with "No error" as the most recent error. */
	result = ext_error_set(NRF_DFU_EXT_ERROR_NO_ERROR);
	UNUSED_RETURN_VALUE(result);

	return NRF_SUCCESS;
}
```



###### nrf_dfu_validation_init_cmd_execute

Source code available on [nrf_dfu_validation.c](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/libraries/bootloader/dfu/nrf_dfu_validation.c)

```c#
nrf_dfu_result_t nrf_dfu_validation_init_cmd_execute(uint32_t * p_dst_data_addr,
                                                     uint32_t * p_data_len)
{
    nrf_dfu_result_t ret_val = NRF_DFU_RES_CODE_SUCCESS;
    if (s_dfu_settings.progress.command_offset != s_dfu_settings.progress.command_size)
    {
        // The object wasn't the right (requested) size.
        NRF_LOG_ERROR("Execute with faulty offset");
        ret_val = NRF_DFU_RES_CODE_OPERATION_NOT_PERMITTED;
    }
    else if (m_valid_init_cmd_present)
    {
        *p_dst_data_addr = nrf_dfu_bank1_start_addr();
        ret_val          = update_data_size_get(mp_init, p_data_len);
    }
    else if (stored_init_cmd_decode())
    {
        // Will only get here if init command was received since last reset.
        // An init command should not be written to flash until after it's been checked here.
        ret_val = nrf_dfu_validation_prevalidate();

        *p_dst_data_addr = 0;
        *p_data_len      = 0;

        // Get size of binary.
        if (ret_val == NRF_DFU_RES_CODE_SUCCESS)
        {
            ret_val = update_data_size_get(mp_init, p_data_len);
        }

        // Get address where to flash the binary.
        if (ret_val == NRF_DFU_RES_CODE_SUCCESS)
        {
            ret_val = update_data_addr_get(mp_init, *p_data_len, p_dst_data_addr);
        }

        // Set flag validating the init command.
        if (ret_val == NRF_DFU_RES_CODE_SUCCESS)
        {
            m_valid_init_cmd_present = true;
        }
        else
        {
            dfu_progress_reset();
        }
    }
    else
    {
        NRF_LOG_ERROR("Failed to decode init packet");
        ret_val = NRF_DFU_RES_CODE_INVALID_OBJECT;
    }

    return ret_val;
}
```




###### postvalidate

Source code available on [nrf_dfu_validation.c](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/libraries/bootloader/dfu/nrf_dfu_validation.c)

```c#
nrf_dfu_result_t postvalidate(uint32_t data_addr, uint32_t data_len, bool is_trusted)
{
    nrf_dfu_result_t           ret_val = NRF_DFU_RES_CODE_SUCCESS;
    dfu_init_command_t const * p_init  = mp_init;
    if (!fw_hash_ok(p_init, data_addr, data_len))
    {
        ret_val = EXT_ERR(NRF_DFU_EXT_ERROR_VERIFICATION_FAILED);
    }
    else
    {
        if (p_init->type == DFU_FW_TYPE_APPLICATION)
        {
            if (!postvalidate_app(p_init, data_addr, data_len, is_trusted))
            {
                ret_val = NRF_DFU_RES_CODE_INVALID_OBJECT;
            }
        }
#if NRF_DFU_SUPPORTS_EXTERNAL_APP
        else if (p_init->type == DFU_FW_TYPE_EXTERNAL_APPLICATION)
        {
            if (!is_trusted)
            {
                // This function must be implemented externally
                ret_val = nrf_dfu_validation_post_external_app_execute(p_init, is_trusted);
            }
            else
            {
                s_dfu_settings.bank_1.bank_code = NRF_DFU_BANK_VALID_EXT_APP;
            }
        }
#endif // NRF_DFU_SUPPORTS_EXTERNAL_APP
        else
        {
            bool with_sd = p_init->type & DFU_FW_TYPE_SOFTDEVICE;
            bool with_bl = p_init->type & DFU_FW_TYPE_BOOTLOADER;
            if (!postvalidate_sd_bl(p_init, with_sd, with_bl, data_addr, data_len, is_trusted))
        	{
            	ret_val = NRF_DFU_RES_CODE_INVALID_OBJECT;
            	if (is_trusted && with_sd && !DFU_REQUIRES_SOFTDEVICE &&
                	(data_addr == nrf_dfu_softdevice_start_address()))
            	{
                	nrf_dfu_softdevice_invalidate();
            	}
        	}
    	}
	}

    if (!is_trusted)
    {
        if (ret_val == NRF_DFU_RES_CODE_SUCCESS)
        {
            s_dfu_settings.bank_current = NRF_DFU_CURRENT_BANK_1;
        }
        else
        {
            dfu_progress_reset();
        }
    }
    else
    {
        if (ret_val == NRF_DFU_RES_CODE_SUCCESS)
        {
            // Mark the update as complete and valid.
            s_dfu_settings.bank_1.image_crc  = crc32_compute((uint8_t *)data_addr, data_len, NULL);
            s_dfu_settings.bank_1.image_size = data_len;
        }
        else
        {
            nrf_dfu_bank_invalidate(&s_dfu_settings.bank_1);
        }

        dfu_progress_reset();
        s_dfu_settings.progress.update_start_address = data_addr;
    }

    return ret_val;
}
```



###### postvalidate_app

Source code available on [nrf_dfu_validation.c](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/libraries/bootloader/dfu/nrf_dfu_validation.c)

```C
static bool postvalidate_app(dfu_init_command_t const * p_init, uint32_t src_addr, uint32_t data_len, bool is_trusted)
{
    boot_validation_t boot_validation;
    ASSERT(p_init->type == DFU_FW_TYPE_APPLICATION);

    if (!boot_validation_extract(&boot_validation, p_init, 0, src_addr, data_len, VALIDATE_CRC))
    {
        return false;
    }
#if !NRF_DFU_IN_APP
    else if (NRF_BL_APP_SIGNATURE_CHECK_REQUIRED &&
             (boot_validation.type != VALIDATE_ECDSA_P256_SHA256))
    {
        NRF_LOG_WARNING("The boot validation of the app must be a signature check.");
        return false;
    }
#endif
    if (!is_trusted)
    {
        return true;
    }

    memcpy(&s_dfu_settings.boot_validation_app, &boot_validation, sizeof(boot_validation));

    s_dfu_settings.bank_1.bank_code = NRF_DFU_BANK_VALID_APP;

    NRF_LOG_DEBUG("Invalidating old application in bank 0.");
    s_dfu_settings.bank_0.bank_code = NRF_DFU_BANK_INVALID;

    if (!DFU_REQUIRES_SOFTDEVICE && !update_requires_softdevice(p_init))
    {
         // App does not need SD, so it should be placed where SD is.
         nrf_dfu_softdevice_invalidate();
    }

    if (!NRF_DFU_DEBUG ||
                (NRF_DFU_DEBUG && (p_init->has_is_debug == false || p_init->is_debug == false)))
    {
        s_dfu_settings.app_version = p_init->fw_version;
    }

    return true;
}
```



###### postvalidate_sd_bl

Source code available on [nrf_dfu_validation.c](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/libraries/bootloader/dfu/nrf_dfu_validation.c)

```c#
static bool postvalidate_sd_bl(dfu_init_command_t const  * p_init,
                               bool                        with_sd,
                               bool                        with_bl,
                               uint32_t                    start_addr,
                               uint32_t                    data_len,
                               bool                        is_trusted)
{
    boot_validation_t boot_validation_sd = {NO_VALIDATION};
    boot_validation_t boot_validation_bl = {NO_VALIDATION};
    uint32_t bl_start = start_addr;
    uint32_t bl_size = data_len;
    
	ASSERT(with_sd || with_bl);

    if (with_sd)
    {
        if (!softdevice_info_ok(start_addr, p_init->sd_size))
        {
            return false;
        }

        if (is_major_softdevice_update(start_addr))
        {
            NRF_LOG_WARNING("Invalidating app because it is incompatible with the SoftDevice.");
            if (DFU_REQUIRES_SOFTDEVICE && !with_bl)
            {
                NRF_LOG_ERROR("Major SD update but no BL. Abort to avoid incapacitating the BL.");
                return false;
            }
        }

        if (!boot_validation_extract(&boot_validation_sd, p_init, 0, start_addr, p_init->sd_size, VALIDATE_CRC))
        {
            return false;
        }

        bl_start += p_init->sd_size;
        bl_size -= p_init->sd_size;
    }
    if (with_bl)
    {
        if (!boot_validation_extract(&boot_validation_bl, p_init, 0, bl_start, bl_size, NO_VALIDATION))
        {
            return false;
        }
        else if (boot_validation_bl.type != NO_VALIDATION)
        {
            NRF_LOG_WARNING("Boot validation of bootloader is not supported and will be ignored.");
        }
    }

    if (!is_trusted)
    {
        return true;
    }

    if (with_sd)
    {
        if (is_major_softdevice_update(start_addr))
        {
            // Invalidate app since it may not be compatible with new SD.
            nrf_dfu_bank_invalidate(&s_dfu_settings.bank_0);
        }

        memcpy(&s_dfu_settings.boot_validation_softdevice, &boot_validation_sd, sizeof(boot_validation_sd));

        // Mark the update as valid.
        s_dfu_settings.bank_1.bank_code = with_bl ? NRF_DFU_BANK_VALID_SD_BL
                                                  : NRF_DFU_BANK_VALID_SD;

        s_dfu_settings.sd_size = p_init->sd_size;
    }
    else
    {
        s_dfu_settings.bank_1.bank_code = NRF_DFU_BANK_VALID_BL;
    }
    
    if (with_bl)
    {
        memcpy(&s_dfu_settings.boot_validation_bootloader, &boot_validation_bl, sizeof(boot_validation_bl));

        if (!NRF_DFU_DEBUG ||
            (NRF_DFU_DEBUG && (p_init->has_is_debug == false || p_init->is_debug == false)))
        {
            // If the update contains a bootloader, update the version.
            // Unless the update is a debug packet.
            s_dfu_settings.bootloader_version = p_init->fw_version;
        }
    }

    return true;
}
```



###### boot_validation_extract

Source code available on [nrf_dfu_validation.c](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/libraries/bootloader/dfu/nrf_dfu_validation.c)

```c#
static bool boot_validation_extract(boot_validation_t * p_boot_validation,
                                    dfu_init_command_t const * p_init,
                                    uint32_t index,
                                    uint32_t start_addr,
                                    uint32_t data_len,
                                    boot_validation_type_t default_type)
{
    ret_code_t err_code;
    size_t     hash_len = NRF_CRYPTO_HASH_SIZE_SHA256;
    
    nrf_crypto_hash_context_t hash_context = {0};

    memset(p_boot_validation, 0, sizeof(boot_validation_t));
    p_boot_validation->type = (p_init->boot_validation_count > index)
                              ? (boot_validation_type_t)p_init->boot_validation[index].type
                              : default_type; // default

    switch(p_boot_validation->type)
    {
        case NO_VALIDATION:
            break;

        case VALIDATE_CRC:
            *(uint32_t *)&p_boot_validation->bytes[0] = crc32_compute((uint8_t *)start_addr, data_len, NULL);
            break;

        case VALIDATE_SHA256:
            err_code = nrf_crypto_hash_calculate(&hash_context,
                                                 &g_nrf_crypto_hash_sha256_info,
                                                 (uint8_t*)start_addr,
                                                 data_len,
                                                 p_boot_validation->bytes,
                                                 &hash_len);
            if (err_code != NRF_SUCCESS)
            {
                NRF_LOG_ERROR("nrf_crypto_hash_calculate() failed with error %s", nrf_strerror_get(err_code));
                return false;
            }
            break;

        case VALIDATE_ECDSA_P256_SHA256:
            memcpy(p_boot_validation->bytes, p_init->boot_validation[index].bytes.bytes, p_init->boot_validation[index].bytes.size);
            break;

        default:
            NRF_LOG_ERROR("Invalid boot validation type: %d", p_boot_validation->type);
            return false;
    }

    return nrf_dfu_validation_boot_validate(p_boot_validation, start_addr, data_len);
}
```



###### nrf_dfu_validation_boot_validate

Source code available on [nrf_dfu_validation.c](https://github.com/DiUS/nRF5-SDK-15.3.0-reduced/blob/master/components/libraries/bootloader/dfu/nrf_dfu_validation.c)

```c#
bool nrf_dfu_validation_boot_validate(boot_validation_t const * p_validation, uint32_t data_addr, uint32_t data_len)
{
    uint8_t const * p_data = (uint8_t*) data_addr;
    switch(p_validation->type)
    {
        case NO_VALIDATION:
            return true;
    case VALIDATE_CRC:
        {
            uint32_t current_crc = *(uint32_t *)p_validation->bytes;
            uint32_t crc = crc32_compute(p_data, data_len, NULL);

            if (crc != current_crc)
            {
                // CRC does not match with what is stored.
                NRF_LOG_DEBUG("CRC check of app failed. Return %d", NRF_DFU_DEBUG);
                return NRF_DFU_DEBUG;
            }
            return true;
        }

        case VALIDATE_SHA256:
            return nrf_dfu_validation_hash_ok(p_validation->bytes, data_addr, data_len, false);

        case VALIDATE_ECDSA_P256_SHA256:
        {
            nrf_dfu_result_t res_code = nrf_dfu_validation_signature_check(
                                            DFU_SIGNATURE_TYPE_ECDSA_P256_SHA256,
                                            p_validation->bytes,
                                            NRF_CRYPTO_ECDSA_SECP256R1_SIGNATURE_SIZE,
                                            p_data,
                                            data_len);
            return (res_code == NRF_DFU_RES_CODE_SUCCESS);
        }

        default:
            ASSERT(false);
            return false;
    }
}
```




#### Running Examples (To do)

###### Running Examples that use a SoftDevice

Programming the SoftDevice on the board is the very first step before moving to more advanced examples that use Bluetooth. Nordic suggests three methods to program the SoftDevice as follow:

* using nRFgo Studio
* from an example project within ARM Keil
* using the GCC makefile of an example



###### Creating a DFU bootloader

This link explains how to [create a DFU bootloader](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.sdk51.v10.0.0%2Fbledfu_bootloader_introduction.html)



###### Running the BLE bootloader Example

This link provides the details on [running BLE bootloader Example](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.sdk51.v10.0.0%2Fbledfu_example_running.html)



#### References

###### Validation

[https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.sdk5.v15.0.0%2Flib_bootloader_dfu_validation.html]

[https://infocenter.nordicsemi.com/index.jsp?topic=%2Fsdk_nrf5_v17.0.2%2Fgroup__nrf__dfu__validation.html&resultof=%22%64%66%75%22%20%22%76%61%6c%69%64%61%74%69%6f%6e%22%20%22%76%61%6c%69%64%22%20]

###### Architecture 

https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.sdk51.v9.0.0%2Fbledfu_architecture_bl.html

###### BLE Secure DFU Bootloader

[https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.sdk5.v15.0.0%2Fble_sdk_app_dfu_bootloader.html]

###### Running Examples

[https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.sdk51.v10.0.0%2Fgetting_started_softdevice.html]
