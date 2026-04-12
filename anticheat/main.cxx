#include <shared/stdafx.hxx>
#include "faultline.hxx"

static Faultline Instance;

DLL_EXPORT void StartFaultline() {
  Instance.Start();
}

DLL_EXPORT void StopFaultline() {
  Instance.Stop();
}
