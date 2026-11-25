/** Generic wording until the device has said which kind of biometrics it has. */
export const GENERIC_BIOMETRIC_LABEL = 'Face ID or fingerprint'

/**
 * What the device calls its biometric unlock, from the plugin's BiometryType:
 * 1 Touch ID, 2 Face ID (and Optic ID), 3 fingerprint, 4 face unlock
 * (Android), anything else → the generic wording.
 */
export function biometricLabel(biometryType: number | undefined): string {
  switch (biometryType) {
    case 1:
      return 'Touch ID'
    case 2:
      return 'Face ID'
    case 3:
      return 'your fingerprint'
    case 4:
      return 'face unlock'
    default:
      return GENERIC_BIOMETRIC_LABEL
  }
}
