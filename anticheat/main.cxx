#include <shared/stdafx.hxx>
#include "faultline.hxx"

static Faultline Instance;

ANTICHEAT_API void StartFaultline() {
  Instance.Start();
}

ANTICHEAT_API void StopFaultline() {
  Instance.Stop();
}
