import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import ManageIOCs from '../views/iocs-manage.vue'

// Prevent real network calls during tests.
vi.mock('axios', () => ({
  default: {
    get: vi.fn().mockResolvedValue({ data: { tags: ['suspect'], types: [] } }),
    post: vi.fn().mockResolvedValue({ data: { status: true } }),
  },
}))

describe('iocs-manage.vue', () => {
  let wrapper

  beforeEach(() => {
    wrapper = mount(ManageIOCs)
  })

  it('mounts without throwing', () => {
    expect(wrapper.exists()).toBe(true)
  })

  it('starts on the bulk tab', () => {
    expect(wrapper.vm.tabs.bulk).toBe(true)
    expect(wrapper.vm.tabs.file).toBe(false)
    expect(wrapper.vm.tabs.export).toBe(false)
  })

  it('switch_tab activates the target tab and deactivates others', () => {
    wrapper.vm.switch_tab('file')
    expect(wrapper.vm.tabs.file).toBe(true)
    expect(wrapper.vm.tabs.bulk).toBe(false)
    expect(wrapper.vm.tabs.export).toBe(false)
  })

  it('import_from_bulk with missing tag/type/tlp sets type_tag_error', () => {
    wrapper.vm.tag = ''
    wrapper.vm.type = ''
    wrapper.vm.tlp = ''
    wrapper.vm.iocs = 'malware.example.com'
    wrapper.vm.import_from_bulk()
    expect(wrapper.vm.type_tag_error).toBe(true)
  })

  it('import_ioc sends a POST to /api/ioc/add_post', async () => {
    const axios = (await import('axios')).default
    axios.post.mockClear()
    wrapper.vm.import_ioc('suspect', 'domain', 'white', 'malware.example.com')
    expect(axios.post).toHaveBeenCalledWith(
      '/api/ioc/add_post',
      expect.objectContaining({ data: expect.any(Object) }),
      expect.any(Object),
    )
  })
})
