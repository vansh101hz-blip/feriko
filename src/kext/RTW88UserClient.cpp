// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// RTW88UserClient.cpp — IOUserClient implementation

#include "RTW88UserClient.hpp"
#include "RTW88PCIDevice.hpp"
#include "RTW88IEEE80211.hpp"

#include <IOKit/IOLib.h>
#include <string.h>

#define super IOUserClient
OSDefineMetaClassAndStructors(RTW88UserClient, IOUserClient)

/* ------------------------------------------------------------------ */
/*  Dispatch table                                                      */
/* ------------------------------------------------------------------ */

const IOExternalMethodDispatch RTW88UserClient::sMethods[kRTW88NumSelectors] = {
    /* kRTW88Scan */
    { (IOExternalMethodAction)&RTW88UserClient::sScan,
      0, 0, 0, 0 },
    /* kRTW88Connect: input struct = RTW88ConnectArgs */
    { (IOExternalMethodAction)&RTW88UserClient::sConnect,
      0, sizeof(RTW88ConnectArgs), 0, 0 },
    /* kRTW88Disconnect */
    { (IOExternalMethodAction)&RTW88UserClient::sDisconnect,
      0, 0, 0, 0 },
    /* kRTW88GetState: output struct = RTW88StateResult */
    { (IOExternalMethodAction)&RTW88UserClient::sGetState,
      0, 0, 0, sizeof(RTW88StateResult) },
    /* kRTW88GetBSSList: output = raw bytes, max 16KB */
    { (IOExternalMethodAction)&RTW88UserClient::sGetBSSList,
      0, 0, 0, 16 * 1024 },
    /* kRTW88GetRSSI: output scalar */
    { (IOExternalMethodAction)&RTW88UserClient::sGetRSSI,
      0, 0, 1, 0 },
    /* kRTW88SetDebug: input scalar = debug level */
    { (IOExternalMethodAction)&RTW88UserClient::sSetDebug,
      1, 0, 0, 0 },
    /* kRTW88GetLog: output = log bytes */
    { (IOExternalMethodAction)&RTW88UserClient::sGetLog,
      0, 0, 0, 4096 },
};

/* ------------------------------------------------------------------ */
/*  Factory                                                             */
/* ------------------------------------------------------------------ */

RTW88UserClient *RTW88UserClient::create(RTW88PCIDevice *dev, task_t owningTask)
{
    RTW88UserClient *uc = new RTW88UserClient;
    if (uc && !uc->init(nullptr)) { uc->release(); return nullptr; }
    if (uc) { uc->_provider = dev; uc->_owningTask = owningTask; }
    return uc;
}

/* ------------------------------------------------------------------ */
/*  IOService lifecycle                                                 */
/* ------------------------------------------------------------------ */

bool RTW88UserClient::init(OSDictionary *props)
{
    return super::init(props);
}

bool RTW88UserClient::initWithTask(task_t owningTask, void *securityID, UInt32 type, OSDictionary *properties)
{
    if (!super::initWithTask(owningTask, securityID, type, properties))
        return false;
    _owningTask = owningTask;
    return true;
}

bool RTW88UserClient::initWithTask(task_t owningTask, void *securityID, UInt32 type)
{
    if (!super::initWithTask(owningTask, securityID, type))
        return false;
    _owningTask = owningTask;
    return true;
}

bool RTW88UserClient::start(IOService *provider)
{
    if (!super::start(provider)) return false;
    _provider = OSDynamicCast(RTW88PCIDevice, provider);
    return _provider != nullptr;
}

void RTW88UserClient::stop(IOService *provider)
{
    super::stop(provider);
}

void RTW88UserClient::free()
{
    super::free();
}

IOReturn RTW88UserClient::clientClose()
{
    terminate();
    return kIOReturnSuccess;
}

/* ------------------------------------------------------------------ */
/*  externalMethod dispatch                                             */
/* ------------------------------------------------------------------ */

IOReturn RTW88UserClient::externalMethod(uint32_t selector,
                                          IOExternalMethodArguments *args,
                                          IOExternalMethodDispatch *dispatch,
                                          OSObject *target, void *reference)
{
    if (selector >= kRTW88NumSelectors)
        return kIOReturnUnsupported;

    const IOExternalMethodDispatch *d = &sMethods[selector];
    return super::externalMethod(selector, args,
                                  const_cast<IOExternalMethodDispatch *>(d),
                                  this, nullptr);
}

/* ------------------------------------------------------------------ */
/*  Individual selectors                                                */
/* ------------------------------------------------------------------ */

IOReturn RTW88UserClient::sScan(RTW88UserClient *uc, void *ref,
                                  IOExternalMethodArguments *args)
{
    if (!uc->_provider || !uc->_provider->get80211()) return kIOReturnNotReady;
    return uc->_provider->get80211()->cmdScan();
}

IOReturn RTW88UserClient::sConnect(RTW88UserClient *uc, void *ref,
                                     IOExternalMethodArguments *args)
{
    if (!uc->_provider || !uc->_provider->get80211()) return kIOReturnNotReady;
    if (!args->structureInput || args->structureInputSize < sizeof(RTW88ConnectArgs))
        return kIOReturnBadArgument;

    const RTW88ConnectArgs *ca = (const RTW88ConnectArgs *)args->structureInput;
    return uc->_provider->get80211()->cmdConnect(ca->ssid, ca->password);
}

IOReturn RTW88UserClient::sDisconnect(RTW88UserClient *uc, void *ref,
                                        IOExternalMethodArguments *args)
{
    if (!uc->_provider || !uc->_provider->get80211()) return kIOReturnNotReady;
    return uc->_provider->get80211()->cmdDisconnect();
}

IOReturn RTW88UserClient::sGetState(RTW88UserClient *uc, void *ref,
                                      IOExternalMethodArguments *args)
{
    if (!uc->_provider || !uc->_provider->get80211()) return kIOReturnNotReady;
    if (!args->structureOutput || args->structureOutputSize < sizeof(RTW88StateResult))
        return kIOReturnBadArgument;

    RTW88StateResult *result = (RTW88StateResult *)args->structureOutput;
    memset(result, 0, sizeof(*result));

    RTW88State state;
    IOReturn ret = uc->_provider->get80211()->cmdGetState(&state);
    if (ret != kIOReturnSuccess) return ret;

    result->state = (uint32_t)state;

    int rssi = -100;
    uc->_provider->get80211()->cmdGetRSSI(&rssi);
    result->rssi = rssi;

    args->structureOutputSize = sizeof(*result);
    return kIOReturnSuccess;
}

IOReturn RTW88UserClient::sGetBSSList(RTW88UserClient *uc, void *ref,
                                        IOExternalMethodArguments *args)
{
    if (!uc->_provider || !uc->_provider->get80211()) return kIOReturnNotReady;
    if (!args->structureOutput) return kIOReturnBadArgument;

    uint32_t len = (uint32_t)args->structureOutputSize;
    IOReturn ret = uc->_provider->get80211()->cmdGetBSSList(
        (uint8_t *)args->structureOutput, &len);
    args->structureOutputSize = len;
    return ret;
}

IOReturn RTW88UserClient::sGetRSSI(RTW88UserClient *uc, void *ref,
                                     IOExternalMethodArguments *args)
{
    if (!uc->_provider || !uc->_provider->get80211()) return kIOReturnNotReady;
    int rssi = -100;
    IOReturn ret = uc->_provider->get80211()->cmdGetRSSI(&rssi);
    if (args->scalarOutput && args->scalarOutputCount >= 1)
        args->scalarOutput[0] = (uint64_t)(int64_t)rssi;
    return ret;
}

IOReturn RTW88UserClient::sSetDebug(RTW88UserClient *uc, void *ref,
                                      IOExternalMethodArguments *args)
{
    if (args->scalarInputCount >= 1) {
        extern int rtw88_log_level;
        rtw88_log_level = (int)args->scalarInput[0];
    }
    return kIOReturnSuccess;
}

IOReturn RTW88UserClient::sGetLog(RTW88UserClient *uc, void *ref,
                                    IOExternalMethodArguments *args)
{
    /* Future: ring-buffer log */
    if (args->structureOutput && args->structureOutputSize >= 5) {
        memcpy(args->structureOutput, "OK\n", 3);
        args->structureOutputSize = 3;
    }
    return kIOReturnSuccess;
}
