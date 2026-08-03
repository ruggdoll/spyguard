import { describe, expect, it, vi } from 'vitest'
import EditConfiguration from '../views/edit-configuration.vue'

vi.mock('axios', () => ({
  default: {
    get: vi.fn().mockResolvedValue({ data: {} }),
    patch: vi.fn().mockResolvedValue({ data: { status: true } }),
  },
}))

// Test methods directly without mounting the full template.
// The template needs a deeply populated config object; testing methods
// in isolation is simpler and focuses on the behaviour that changed in task 9.

describe('edit-configuration.vue methods', () => {
  it('switch_config calls axios.patch not axios.get', async () => {
    const axios = (await import('axios')).default
    axios.patch.mockClear()

    // Call the method with a minimal `this` context.
    await EditConfiguration.methods.switch_config.call({ jwt: 'token' }, 'analysis', 'heuristics')

    expect(axios.patch).toHaveBeenCalledWith(
      '/api/config/switch/analysis/heuristics',
      {},
      expect.any(Object),
    )
    expect(axios.get).not.toHaveBeenCalled()
  })

  it('change_spyguard_server calls axios.patch with value in body', async () => {
    const axios = (await import('axios')).default
    axios.patch.mockClear()

    await EditConfiguration.methods.change_spyguard_server.call(
      { jwt: 'token', config: { frontend: { spyguard_server: 'https://new.host' } } },
    )

    expect(axios.patch).toHaveBeenCalledWith(
      '/api/config/edit/frontend/spyguard_server',
      { value: 'https://new.host' },
      expect.any(Object),
    )
  })
})
