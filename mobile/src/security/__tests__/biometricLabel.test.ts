import { describe, it, expect } from 'vitest'
import { GENERIC_BIOMETRIC_LABEL, biometricLabel } from '../biometricLabel'

describe('biometricLabel', () => {
  it('names the device biometrics', () => {
    expect(biometricLabel(1)).toBe('Touch ID')
    expect(biometricLabel(2)).toBe('Face ID')
    expect(biometricLabel(3)).toBe('your fingerprint')
    expect(biometricLabel(4)).toBe('face unlock')
    expect(biometricLabel(undefined)).toBe(GENERIC_BIOMETRIC_LABEL)
    expect(biometricLabel(6)).toBe(GENERIC_BIOMETRIC_LABEL)
  })
})
