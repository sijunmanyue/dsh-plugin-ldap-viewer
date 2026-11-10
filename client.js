/**
 * Client half of the LDAP Viewer.
 *
 * A full main-panel page plus a sidebar entry:
 *   sidebar.panellist -> menu icon, id "ldap-viewer"
 *   main              -> page, key "ldap-viewer"
 *
 * The Host half owns the LDAP socket and the bind password. This module only
 * talks to the loopback JSON route at /api/ldap-viewer.
 */

window.__ModuleLoader__.load({
  id: '@local/ldap-viewer',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useState, useEffect, useMemo, useRef, useReducer } = React

    const NS = 'ldap-viewer'
    const API = '/api/ldap-viewer'
    const PANEL_ID = 'ldap-viewer'
    const MAX_RESULTS = 500
    const PAGE_SIZE_OPTIONS = [10, 20, 50]

    const MESSAGES = {
      zh: {
        appTitle: 'LDAP 账号查看器',
        appSubtitle: '只读查询 Active Directory 中的账号，分列查看启用、锁定、账号有效期和密码过期等状态。',
        readOnly: '只读',
        edit: '编辑',
        cancel: '取消',
        save: '保存',
        saving: '保存中…',
        configTitle: '连接配置',
        configSubtitle: '默认只读；点击编辑可修改。绑定密码只保存在 Harness 凭据库中。',
        server: '服务器',
        baseDn: 'Base DN',
        bindDn: 'Bind DN',
        bindPassword: '绑定密码',
        passwordConfigured: '已配置',
        passwordNotConfigured: '未配置',
        sourceStore: '凭据库',
        sourceEnvironment: '环境变量',
        ldap: 'LDAP',
        host: '主机',
        hostPlaceholder: '例如 ldap.example.com',
        port: '端口',
        baseDnPlaceholder: '例如 DC=example,DC=com',
        bindDnPlaceholder: '例如 CN=service-account,CN=Users,DC=example,DC=com',
        passwordPlaceholder: '输入绑定密码',
        passwordKeepHint: '留空则保持当前密码。',
        configNote: '连接信息保存在本机配置文件中；密码不会回显到页面。',
        configSaved: '配置已保存',
        configLoadFailed: '加载连接配置失败',
        retry: '重试',
        passwordWarning: '尚未配置绑定密码，查询前请点击“编辑”设置。',
        queryTitle: '账号查询',
        querySubtitle: '支持按账号、邮箱或手机号精确查询；查询只读，不会修改 LDAP。',
        queryType: '查询条件',
        account: '账号',
        email: '邮箱',
        mobile: '手机号',
        queryPlaceholderAccount: '例如 S13800000000',
        queryPlaceholderEmail: '例如 name@example.com',
        queryPlaceholderMobile: '例如 13800000000',
        search: '查询',
        searching: '查询中…',
        queryValueRequired: '请输入要查询的账号、邮箱或手机号。',
        exactMatch: '精确匹配',
        maxResults: '最多返回 {max} 条',
        initialTitle: '输入条件开始查询',
        initialBody: '可以按账号、邮箱或手机号查找目录账号。',
        noResultsTitle: '没有找到匹配账号',
        noResultsBody: '请检查输入是否完整，或换一个查询条件。',
        resultCount: '共 {count} 条结果',
        pageInfo: '第 {page} / {pages} 页',
        prev: '上一页',
        next: '下一页',
        pageSize: '每页',
        perPage: '{size} 条',
        truncated: '结果超过 {max} 条，仅显示前 {max} 条。请缩小查询范围。',
        queryNote: '仅执行 LDAP 读取操作。',
        queryError: '查询失败',
        tookTime: '耗时 {ms} ms',
        serverLabel: '服务器：{server}',
        colAccount: '账号 / 姓名',
        colEmail: '邮箱',
        colMobile: '手机号',
        colDepartment: '部门',
        colEnabled: '已启用',
        colLock: '锁定状态',
        colAccountExpiry: '账号有效期',
        colPassword: '密码状态',
        enabledYes: '是',
        enabledNo: '否',
        unlocked: '正常',
        locked: '已锁定',
        accountActive: '未过期',
        accountExpired: '已过期',
        disabled: '已禁用',
        passwordValid: '正常',
        passwordExpired: '已过期',
        passwordMustChange: '需修改',
        passwordNever: '永不过期',
        passwordUnknown: '未知',
        expiresAt: '到期：{date}',
        expiredAt: '过期于：{date}',
        noExpiry: '永不过期',
        neverExpires: '永不过期',
        accountExpiryNever: '账号不过期',
        accountExpiryAt: '账号有效期至 {date}',
        lockedAt: '锁定时间：{date}',
        passwordMustChangeHint: '下次登录需修改密码',
        passwordUnknownHint: '缺少密码过期属性',
        lastLogon: '最近登录',
        createdAt: '创建时间',
        dn: 'DN',
        pwdLastSet: '密码设置时间',
        notAvailable: '—',
        emptyEmail: '未填写',
        emptyMobile: '未填写',
        emptyDepartment: '未填写',
        statusUnknown: '未知',
        a11yEdit: '编辑连接配置',
        a11ySave: '保存连接配置',
        a11yCancel: '取消编辑',
        a11yShowPassword: '显示密码',
        a11yHidePassword: '隐藏密码',
        a11yQuery: '查询 LDAP 账号',
        a11yPage: '第 {page} 页',
        errorNetwork: '无法连接本地 LDAP 查看器服务，请确认插件 Host 半边已加载。',
        errorPasswordRequired: '尚未配置绑定密码，请先在上方配置区设置。',
        errorValidation: '输入内容不完整或格式不正确。',
        errorInvalidBody: '请求内容格式不正确。',
        errorBodyTooLarge: '请求内容过大。',
        errorUnsupportedMediaType: '请求类型不正确。',
        errorForbidden: '该接口只允许本机访问。',
        errorCredentialStore: '无法访问 Harness 凭据库，请检查 Host 服务。',
        errorConfigIo: '无法读写连接配置文件，请检查 DSH_HOME 权限。',
        errorLdapInvalidCredentials: 'LDAP 绑定失败：Bind DN 或密码不正确。',
        errorLdapUnreachable: '无法连接 LDAP 服务器，请检查主机、端口和网络。',
        errorLdapTimeout: 'LDAP 查询超时，请检查网络或缩短查询范围。',
        errorLdapNoSuchObject: 'Base DN 不存在，或当前账号无权访问该目录。',
        errorLdapInsufficientAccess: 'LDAP 账号权限不足，无法执行查询。',
        errorLdapUnsupportedControl: 'LDAP 服务器不支持分页查询。',
        errorLdapSizeLimit: 'LDAP 服务器返回的结果数量超过限制。',
        errorLdapTimeLimit: 'LDAP 服务器执行查询超时。',
        errorLdapProtocol: 'LDAP 响应格式异常。',
        errorLdapError: 'LDAP 查询失败。',
        errorInternal: '服务内部错误。',
        errorUnknown: '发生未知错误。',
        errorRender: '页面渲染失败，请刷新窗口后重试。',
      },
      en: {
        appTitle: 'LDAP Account Viewer',
        appSubtitle: 'Read-only lookup of accounts in Active Directory, with separate columns for enabled, lock, account-expiry, and password-expiry states.',
        readOnly: 'Read-only',
        edit: 'Edit',
        cancel: 'Cancel',
        save: 'Save',
        saving: 'Saving…',
        configTitle: 'Connection settings',
        configSubtitle: 'Read-only by default; choose Edit to change. The bind password is stored only in the Harness credential store.',
        server: 'Server',
        baseDn: 'Base DN',
        bindDn: 'Bind DN',
        bindPassword: 'Bind password',
        passwordConfigured: 'Configured',
        passwordNotConfigured: 'Not configured',
        sourceStore: 'credential store',
        sourceEnvironment: 'environment variable',
        ldap: 'LDAP',
        host: 'Host',
        hostPlaceholder: 'e.g. ldap.example.com',
        port: 'Port',
        baseDnPlaceholder: 'e.g. DC=example,DC=com',
        bindDnPlaceholder: 'e.g. CN=service-account,CN=Users,DC=example,DC=com',
        passwordPlaceholder: 'Enter the bind password',
        passwordKeepHint: 'Leave blank to keep the current password.',
        configNote: 'Connection settings are stored in a local config file; the password is never returned to this page.',
        configSaved: 'Settings saved',
        configLoadFailed: 'Could not load connection settings',
        retry: 'Retry',
        passwordWarning: 'No bind password is configured. Choose Edit before querying.',
        queryTitle: 'Account lookup',
        querySubtitle: 'Search by exact account, email, or mobile. The query is read-only and never changes LDAP.',
        queryType: 'Search by',
        account: 'Account',
        email: 'Email',
        mobile: 'Mobile',
        queryPlaceholderAccount: 'e.g. S13800000000',
        queryPlaceholderEmail: 'e.g. name@example.com',
        queryPlaceholderMobile: 'e.g. 13800000000',
        search: 'Search',
        searching: 'Searching…',
        queryValueRequired: 'Enter an account, email, or mobile number to search.',
        exactMatch: 'Exact match',
        maxResults: 'Up to {max} results',
        initialTitle: 'Enter a value to begin',
        initialBody: 'Look up a directory account by account name, email, or mobile.',
        noResultsTitle: 'No matching account',
        noResultsBody: 'Check that the value is complete, or try another search type.',
        resultCount: '{count} results',
        pageInfo: 'Page {page} of {pages}',
        prev: 'Previous',
        next: 'Next',
        pageSize: 'Per page',
        perPage: '{size}',
        truncated: 'More than {max} results; only the first {max} are shown. Narrow the query.',
        queryNote: 'LDAP read operations only.',
        queryError: 'Lookup failed',
        tookTime: '{ms} ms',
        serverLabel: 'Server: {server}',
        colAccount: 'Account / Name',
        colEmail: 'Email',
        colMobile: 'Mobile',
        colDepartment: 'Department',
        colEnabled: 'Enabled',
        colLock: 'Lock status',
        colAccountExpiry: 'Account expiry',
        colPassword: 'Password status',
        enabledYes: 'Yes',
        enabledNo: 'No',
        unlocked: 'Normal',
        locked: 'Locked',
        accountActive: 'Not expired',
        accountExpired: 'Expired',
        disabled: 'Disabled',
        passwordValid: 'Valid',
        passwordExpired: 'Expired',
        passwordMustChange: 'Must change',
        passwordNever: 'Never expires',
        passwordUnknown: 'Unknown',
        expiresAt: 'Expires: {date}',
        expiredAt: 'Expired: {date}',
        noExpiry: 'Never expires',
        neverExpires: 'Never expires',
        accountExpiryNever: 'Account never expires',
        accountExpiryAt: 'Account expires {date}',
        lockedAt: 'Locked: {date}',
        passwordMustChangeHint: 'Change required at next sign-in',
        passwordUnknownHint: 'Password-expiry attribute is missing',
        lastLogon: 'Last logon',
        createdAt: 'Created',
        dn: 'DN',
        pwdLastSet: 'Password set',
        notAvailable: '—',
        emptyEmail: 'Not set',
        emptyMobile: 'Not set',
        emptyDepartment: 'Not set',
        statusUnknown: 'Unknown',
        a11yEdit: 'Edit connection settings',
        a11ySave: 'Save connection settings',
        a11yCancel: 'Cancel editing',
        a11yShowPassword: 'Show password',
        a11yHidePassword: 'Hide password',
        a11yQuery: 'Query LDAP accounts',
        a11yPage: 'Page {page}',
        errorNetwork: 'Could not reach the local LDAP Viewer service. Check that the plugin Host half is loaded.',
        errorPasswordRequired: 'No bind password is configured. Set one in the connection settings first.',
        errorValidation: 'The input is incomplete or malformed.',
        errorInvalidBody: 'The request body is malformed.',
        errorBodyTooLarge: 'The request body is too large.',
        errorUnsupportedMediaType: 'The request content type is not supported.',
        errorForbidden: 'This endpoint accepts local requests only.',
        errorCredentialStore: 'The Harness credential store is unavailable.',
        errorConfigIo: 'Could not read or write the connection config file. Check DSH_HOME permissions.',
        errorLdapInvalidCredentials: 'LDAP bind failed: check the Bind DN and password.',
        errorLdapUnreachable: 'Could not reach the LDAP server. Check the host, port, and network.',
        errorLdapTimeout: 'The LDAP request timed out. Check the network or narrow the query.',
        errorLdapNoSuchObject: 'The Base DN does not exist, or this account cannot access it.',
        errorLdapInsufficientAccess: 'The LDAP account has insufficient permission for this query.',
        errorLdapUnsupportedControl: 'The LDAP server does not support paged results.',
        errorLdapSizeLimit: 'The LDAP server returned more results than allowed.',
        errorLdapTimeLimit: 'The LDAP server timed out while running the query.',
        errorLdapProtocol: 'The LDAP response was malformed.',
        errorLdapError: 'The LDAP query failed.',
        errorInternal: 'Internal service error.',
        errorUnknown: 'An unknown error occurred.',
        errorRender: 'The page failed to render. Refresh the window and try again.',
      },
    }

    const ERROR_KEYS = {
      NETWORK: 'errorNetwork',
      PASSWORD_REQUIRED: 'errorPasswordRequired',
      VALIDATION: 'errorValidation',
      INVALID_BODY: 'errorInvalidBody',
      BODY_TOO_LARGE: 'errorBodyTooLarge',
      UNSUPPORTED_MEDIA_TYPE: 'errorUnsupportedMediaType',
      FORBIDDEN: 'errorForbidden',
      CREDENTIAL_STORE: 'errorCredentialStore',
      CONFIG_IO: 'errorConfigIo',
      LDAP_INVALID_CREDENTIALS: 'errorLdapInvalidCredentials',
      LDAP_UNREACHABLE: 'errorLdapUnreachable',
      LDAP_TIMEOUT: 'errorLdapTimeout',
      LDAP_NO_SUCH_OBJECT: 'errorLdapNoSuchObject',
      LDAP_INSUFFICIENT_ACCESS: 'errorLdapInsufficientAccess',
      LDAP_UNAVAILABLE_CRITICAL_EXTENSION: 'errorLdapUnsupportedControl',
      LDAP_SIZELIMIT_EXCEEDED: 'errorLdapSizeLimit',
      LDAP_TIMELIMIT_EXCEEDED: 'errorLdapTimeLimit',
      LDAP_PROTOCOL: 'errorLdapProtocol',
      LDAP_ERROR: 'errorLdapError',
      INTERNAL_ERROR: 'errorInternal',
      HTTP_403: 'errorForbidden',
      HTTP_404: 'errorNetwork',
    }

    function isZh(localeId) {
      return String(localeId || '').toLowerCase().startsWith('zh')
    }

    function useLocaleTick(ctx) {
      const [, forceRender] = useReducer((value) => value + 1, 0)
      useEffect(() => ctx.locale.subscribe(forceRender), [ctx])
    }

    function makeTranslator(ctx) {
      const bound = ctx.locale.bind(NS)
      return (key, values) => {
        let text = bound(key)
        if (!text || text === key) {
          const active = String(ctx.locale.getSnapshot().active || '')
          const dictionary = isZh(active) ? MESSAGES.zh : MESSAGES.en
          text = dictionary[key] || MESSAGES.en[key] || key
        }
        if (values && typeof text === 'string') {
          for (const [name, value] of Object.entries(values)) {
            text = text.replaceAll(`{${name}}`, String(value))
          }
        }
        return text
      }
    }

    async function request(path, options = {}) {
      const init = { cache: 'no-store', ...options }
      if (init.body !== undefined && init.body !== null) {
        init.headers = { 'content-type': 'application/json', ...(init.headers || {}) }
      }
      let response
      try {
        response = await fetch(API + path, init)
      } catch (cause) {
        const error = new Error('network request failed')
        error.code = 'NETWORK'
        error.cause = cause
        throw error
      }

      let payload = null
      const contentType = response.headers.get('content-type') || ''
      if (contentType.includes('application/json')) {
        try { payload = await response.json() } catch { payload = null }
      }
      if (!response.ok || !payload || payload.ok === false) {
        const error = new Error((payload && payload.message) || `HTTP ${response.status}`)
        error.code = (payload && payload.code) || `HTTP_${response.status}`
        error.status = response.status
        error.detail = payload && payload.detail
        throw error
      }
      return payload
    }

    function formatDate(value, lang) {
      if (!value) return null
      const date = new Date(value)
      if (Number.isNaN(date.getTime())) return null
      try {
        return new Intl.DateTimeFormat(lang, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
      } catch {
        return date.toLocaleString()
      }
    }

    function formatNumber(value, lang) {
      try { return new Intl.NumberFormat(lang).format(value) } catch { return String(value) }
    }

    function errorCopy(error, t) {
      const key = error && error.code ? ERROR_KEYS[error.code] : null
      let message = key ? t(key) : null
      if (!message) {
        message = error && error.code && error.code.startsWith('HTTP_')
          ? t('errorInternal')
          : (error && error.message ? error.message : t('errorUnknown'))
      }
      let detail = error && error.detail ? String(error.detail).trim() : ''
      if (detail.length > 400) detail = `${detail.slice(0, 397)}…`
      return { message, detail }
    }

    function Badge({ tone = 'neutral', children, title }) {
      return h('span', { className: `ldv-badge ${tone}`, title }, h('span', { className: 'ldv-dot' }), children)
    }

    function ErrorLine({ error, t }) {
      if (!error) return null
      const copy = errorCopy(error, t)
      return h(
        'div',
        { className: 'ldv-error', role: 'alert' },
        h(AlertGlyph, { size: 15 }),
        h(
          'div',
          { className: 'ldv-error-text' },
          h('span', null, copy.message),
          copy.detail ? h('span', { className: 'ldv-error-detail' }, copy.detail) : null,
        ),
      )
    }

    function EmptyState({ icon, title, body }) {
      return h(
        'div',
        { className: 'ldv-empty' },
        h('div', { className: 'ldv-empty-icon' }, icon),
        h('h3', null, title),
        body ? h('p', null, body) : null,
      )
    }

    function AlertGlyph({ size = 16 }) {
      return h(
        'svg',
        { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': true, focusable: false },
        h('circle', { cx: 12, cy: 12, r: 8.5, stroke: 'currentColor', strokeWidth: 1.7 }),
        h('path', { d: 'M12 7.7v5.2', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' }),
        h('circle', { cx: 12, cy: 16.4, r: 1, fill: 'currentColor' }),
      )
    }

    function ServerGlyph({ size = 18 }) {
      return h(
        'svg',
        { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': true, focusable: false },
        h('rect', { x: 4, y: 4, width: 16, height: 6.2, rx: 1.6, stroke: 'currentColor', strokeWidth: 1.6 }),
        h('rect', { x: 4, y: 13.8, width: 16, height: 6.2, rx: 1.6, stroke: 'currentColor', strokeWidth: 1.6 }),
        h('path', { d: 'M7.4 7.1h.01M7.4 16.9h.01M11 7.1h5.2M11 16.9h5.2', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' }),
      )
    }

    function SearchGlyph({ size = 16 }) {
      return h(
        'svg',
        { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': true, focusable: false },
        h('circle', { cx: 10.8, cy: 10.8, r: 6.2, stroke: 'currentColor', strokeWidth: 1.8 }),
        h('path', { d: 'm15.5 15.5 4.2 4.2', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' }),
      )
    }

    function EditGlyph({ size = 14 }) {
      return h(
        'svg',
        { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': true, focusable: false },
        h('path', { d: 'M4.5 19.5h4.1L19 9.1a2.1 2.1 0 0 0-3-3L5.7 16.4l-1.2 3.1Z', stroke: 'currentColor', strokeWidth: 1.7, strokeLinejoin: 'round' }),
        h('path', { d: 'm14.4 7.8 2.8 2.8', stroke: 'currentColor', strokeWidth: 1.7 }),
      )
    }

    function EyeGlyph({ off = false, size = 15 }) {
      return h(
        'svg',
        { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': true, focusable: false },
        h('path', { d: 'M2.6 12s3.4-6.2 9.4-6.2S21.4 12 21.4 12s-3.4 6.2-9.4 6.2S2.6 12 2.6 12Z', stroke: 'currentColor', strokeWidth: 1.6, strokeLinejoin: 'round' }),
        h('circle', { cx: 12, cy: 12, r: 2.7, stroke: 'currentColor', strokeWidth: 1.6 }),
        off ? h('path', { d: 'm4 4 16 16', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' }) : null,
      )
    }

    function RefreshGlyph({ size = 14 }) {
      return h(
        'svg',
        { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': true, focusable: false },
        h('path', { d: 'M19 8.5A8 8 0 1 0 20 12', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round' }),
        h('path', { d: 'M19.5 4.8v4.4h-4.4', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round', strokeLinejoin: 'round' }),
      )
    }

    function SidebarIcon({ size = 20, active = false }) {
      return h(
        'svg',
        {
          width: size,
          height: size,
          viewBox: '0 0 24 24',
          fill: 'none',
          'aria-hidden': true,
          focusable: false,
          style: { display: 'block', opacity: active ? 1 : 0.84 },
        },
        h('rect', { x: 3.2, y: 4.4, width: 17.6, height: 5.4, rx: 1.5, stroke: 'currentColor', strokeWidth: 1.6 }),
        h('rect', { x: 3.2, y: 12.2, width: 17.6, height: 5.4, rx: 1.5, stroke: 'currentColor', strokeWidth: 1.6 }),
        h('circle', { cx: 6.5, cy: 7.1, r: 0.9, fill: 'currentColor' }),
        h('circle', { cx: 6.5, cy: 14.9, r: 0.9, fill: 'currentColor' }),
        h('path', { d: 'M9.5 7.1h6.1M9.5 14.9h4.4', stroke: 'currentColor', strokeWidth: 1.6, strokeLinecap: 'round' }),
      )
    }

    function InfoField({ label, value, mono = false, wide = false, action = null }) {
      return h(
        'div',
        { className: 'ldv-info' + (wide ? ' wide' : '') },
        h('div', { className: 'ldv-info-label' }, label),
        h(
          'div',
          { className: 'ldv-info-value' + (mono ? ' mono' : '') },
          h('span', { className: 'ldv-info-text', title: typeof value === 'string' ? value : undefined }, value),
          action,
        ),
      )
    }

    function Field({ label, hint, htmlFor, children, full = false }) {
      return h(
        'div',
        { className: 'ldv-field' + (full ? ' full' : '') },
        h('label', { htmlFor }, label),
        children,
        hint ? h('p', { className: 'ldv-hint' }, hint) : null,
      )
    }

    function ConfigCard({
      t,
      config,
      password,
      loading,
      loadError,
      editing,
      draft,
      saving,
      formError,
      showPassword,
      configSaved,
      onRetry,
      onStartEdit,
      onCancel,
      onSave,
      onDraftChange,
      onTogglePassword,
    }) {
      if (loading) {
        return h(
          'section',
          { className: 'ldv-card' },
          h('div', { className: 'ldv-loading' }, h('span', { className: 'ldv-spinner' }), t('configTitle')),
        )
      }

      if (!config) {
        return h(
          'section',
          { className: 'ldv-card' },
          h('div', { className: 'ldv-card-head' }, h('div', null, h('h2', null, t('configTitle')), h('p', { className: 'ldv-card-sub' }, t('configLoadFailed')))),
          h(ErrorLine, { error: loadError, t }),
          h('button', { type: 'button', className: 'ldv-btn', onClick: onRetry }, h(RefreshGlyph), t('retry')),
        )
      }

      const serverValue = h(
        'span',
        { className: 'ldv-server-value' },
        h('span', { className: 'ldv-mini-tag' }, t('ldap')),
        h('span', null, `${config.host}:${config.port}`),
      )
      const passwordValue = password.configured
        ? h(
            'span',
            { className: 'ldv-inline-status success' },
            h('span', { className: 'ldv-dot' }),
            t('passwordConfigured'),
            password.source ? h('span', { className: 'ldv-source' }, password.source === 'environment' ? t('sourceEnvironment') : t('sourceStore')) : null,
          )
        : h(
            'span',
            { className: 'ldv-inline-status danger' },
            h('span', { className: 'ldv-dot' }),
            t('passwordNotConfigured'),
          )
      return h(
        'section',
        { className: 'ldv-card' },
        h(
          'div',
          { className: 'ldv-card-head' },
          h(
            'div',
            null,
            h(
              'div',
              { className: 'ldv-title-row' },
              h('h2', null, t('configTitle')),
              editing ? null : h('span', { className: 'ldv-readonly' }, t('readOnly')),
              configSaved ? h('span', { className: 'ldv-saved' }, t('configSaved')) : null,
            ),
            h('p', { className: 'ldv-card-sub' }, t('configSubtitle')),
          ),
          editing
            ? h(
                'div',
                { className: 'ldv-actions' },
                h('button', { type: 'button', className: 'ldv-btn', onClick: onCancel, disabled: saving, title: t('a11yCancel') }, t('cancel')),
                h('button', { type: 'button', className: 'ldv-btn primary', onClick: onSave, disabled: saving, title: t('a11ySave') }, saving ? t('saving') : t('save')),
              )
            : h(
                'div',
                { className: 'ldv-actions' },
                h('button', { type: 'button', className: 'ldv-btn', onClick: onStartEdit, title: t('a11yEdit') }, h(EditGlyph), t('edit')),
              ),
        ),
        editing
          ? h(
              'div',
              { className: 'ldv-form-grid' },
              h(Field, { label: t('host'), htmlFor: 'ldv-host', hint: t('hostPlaceholder') },
                h('input', {
                  id: 'ldv-host',
                  className: 'ldv-input',
                  value: draft.host,
                  spellCheck: false,
                  autoComplete: 'off',
                  onChange: (event) => onDraftChange('host', event.target.value),
                }),
              ),
              h(Field, { label: t('port'), htmlFor: 'ldv-port' },
                h('input', {
                  id: 'ldv-port',
                  className: 'ldv-input',
                  type: 'number',
                  min: 1,
                  max: 65535,
                  step: 1,
                  value: draft.port,
                  onChange: (event) => onDraftChange('port', event.target.value),
                }),
              ),
              h(Field, { label: t('baseDn'), htmlFor: 'ldv-base-dn', hint: t('baseDnPlaceholder'), full: true },
                h('input', {
                  id: 'ldv-base-dn',
                  className: 'ldv-input mono',
                  value: draft.baseDn,
                  spellCheck: false,
                  autoComplete: 'off',
                  onChange: (event) => onDraftChange('baseDn', event.target.value),
                }),
              ),
              h(Field, { label: t('bindDn'), htmlFor: 'ldv-bind-dn', hint: t('bindDnPlaceholder'), full: true },
                h('input', {
                  id: 'ldv-bind-dn',
                  className: 'ldv-input mono',
                  value: draft.bindDn,
                  spellCheck: false,
                  autoComplete: 'off',
                  onChange: (event) => onDraftChange('bindDn', event.target.value),
                }),
              ),
              h(Field, { label: t('bindPassword'), htmlFor: 'ldv-password', hint: t('passwordKeepHint'), full: true },
                h(
                  'div',
                  { className: 'ldv-password-wrap' },
                  h('input', {
                    id: 'ldv-password',
                    className: 'ldv-input',
                    type: showPassword ? 'text' : 'password',
                    value: draft.password,
                    placeholder: t('passwordPlaceholder'),
                    autoComplete: 'new-password',
                    spellCheck: false,
                    onChange: (event) => onDraftChange('password', event.target.value),
                  }),
                  h(
                    'button',
                    {
                      type: 'button',
                      className: 'ldv-eye',
                      onClick: onTogglePassword,
                      title: showPassword ? t('a11yHidePassword') : t('a11yShowPassword'),
                      'aria-label': showPassword ? t('a11yHidePassword') : t('a11yShowPassword'),
                    },
                    h(EyeGlyph, { off: showPassword }),
                  ),
                ),
              ),
            )
          : h(
              'div',
              { className: 'ldv-info-grid' },
              h(InfoField, { label: t('server'), value: serverValue, wide: true }),
              h(InfoField, { label: t('bindPassword'), value: passwordValue }),
              h(InfoField, { label: t('baseDn'), value: config.baseDn || t('notAvailable'), mono: true, wide: true }),
              h(InfoField, { label: t('bindDn'), value: config.bindDn || t('notAvailable'), mono: true, wide: true }),
            ),
        h(ErrorLine, { error: formError || loadError, t }),
        password.configured
          ? null
          : h(
              'div',
              { className: 'ldv-warning' },
              h(AlertGlyph, { size: 15 }),
              h('span', null, t('passwordWarning')),
            ),
        h('div', { className: 'ldv-card-foot' }, t('configNote')),
      )
    }

    function PasswordCell({ entry, t, lang }) {
      const status = entry.passwordStatus
      const labelKey = {
        valid: 'passwordValid',
        expired: 'passwordExpired',
        mustChange: 'passwordMustChange',
        never: 'passwordNever',
        unknown: 'passwordUnknown',
      }[status] || 'passwordUnknown'
      const tone = {
        valid: 'success',
        expired: 'danger',
        mustChange: 'warn',
        never: 'neutral',
        unknown: 'idle',
      }[status] || 'idle'
      let note = null
      if (status === 'valid' && entry.passwordExpiresAt) {
        note = t('expiresAt', { date: formatDate(entry.passwordExpiresAt, lang) || entry.passwordExpiresAt })
      } else if (status === 'expired' && entry.passwordExpiresAt) {
        note = t('expiredAt', { date: formatDate(entry.passwordExpiresAt, lang) || entry.passwordExpiresAt })
      } else if (status === 'mustChange') {
        note = t('passwordMustChangeHint')
      } else if (status === 'unknown') {
        note = t('passwordUnknownHint')
      }
      const title = [
        entry.pwdLastSetAt ? `${t('pwdLastSet')}: ${formatDate(entry.pwdLastSetAt, lang) || entry.pwdLastSetAt}` : null,
        entry.passwordExpiresAt ? `${t('expiresAt', { date: formatDate(entry.passwordExpiresAt, lang) || entry.passwordExpiresAt })}` : null,
      ].filter(Boolean).join('\n')
      return h(
        'div',
        { className: 'ldv-cell-stack', title: title || undefined },
        h(Badge, { tone }, t(labelKey)),
        note ? h('span', { className: 'ldv-cell-note' }, note) : null,
      )
    }

    function LockCell({ entry, t, lang }) {
      let label = t('unlocked')
      let tone = 'success'
      let note = null
      if (entry.locked) {
        label = t('locked')
        tone = 'warn'
        if (entry.lockoutAt) {
          note = t('lockedAt', { date: formatDate(entry.lockoutAt, lang) || entry.lockoutAt })
        }
      } else if (entry.lockState === 'unknown') {
        label = t('statusUnknown')
        tone = 'idle'
      }
      return h(
        'div',
        { className: 'ldv-cell-stack' },
        h(Badge, { tone }, label),
        note ? h('span', { className: 'ldv-cell-note' }, note) : null,
      )
    }

    function AccountExpiryCell({ entry, t, lang }) {
      let label = t('statusUnknown')
      let tone = 'idle'
      let note = null
      if (entry.accountExpired) {
        label = t('accountExpired')
        tone = 'danger'
        if (entry.accountExpiresAt) {
          note = t('accountExpiryAt', { date: formatDate(entry.accountExpiresAt, lang) || entry.accountExpiresAt })
        }
      } else if (entry.accountExpiresAt) {
        label = t('accountActive')
        tone = 'success'
        note = t('accountExpiryAt', { date: formatDate(entry.accountExpiresAt, lang) || entry.accountExpiresAt })
      } else if (entry.accountNeverExpires && entry.accountExpiresRaw !== null) {
        label = t('neverExpires')
        tone = 'neutral'
      }
      return h(
        'div',
        { className: 'ldv-cell-stack' },
        h(Badge, { tone }, label),
        note ? h('span', { className: 'ldv-cell-note' }, note) : null,
      )
    }

    function UserRow({ entry, t, lang }) {
      const name = entry.name && entry.name !== entry.account ? entry.name : null
      return h(
        'tr',
        null,
        h(
          'td',
          null,
          h(
            'div',
            { className: 'ldv-account-cell', title: entry.dn || entry.account },
            h('span', { className: 'ldv-account' }, entry.account),
            name ? h('span', { className: 'ldv-name' }, name) : null,
          ),
        ),
        h('td', null, entry.email ? h('span', { className: 'ldv-truncate', title: entry.email }, entry.email) : h('span', { className: 'ldv-muted' }, t('notAvailable'))),
        h('td', null, entry.mobile ? h('span', { className: 'ldv-mono', title: entry.mobile }, entry.mobile) : h('span', { className: 'ldv-muted' }, t('notAvailable'))),
        h('td', null, entry.department ? h('span', { className: 'ldv-truncate', title: entry.department }, entry.department) : h('span', { className: 'ldv-muted' }, t('notAvailable'))),
        h(
          'td',
          null,
          h(
            'div',
            { className: 'ldv-cell-stack' },
            h(Badge, { tone: entry.enabled ? 'success' : 'idle' }, entry.enabled ? t('enabledYes') : t('enabledNo')),
            entry.disabled ? h('span', { className: 'ldv-cell-note' }, t('disabled')) : null,
          ),
        ),
        h('td', null, h(LockCell, { entry, t, lang })),
        h('td', null, h(AccountExpiryCell, { entry, t, lang })),
        h('td', null, h(PasswordCell, { entry, t, lang })),
      )
    }

    function buildPageWindow(current, total) {
      if (total <= 7) return Array.from({ length: total }, (_, index) => index + 1)
      const pages = new Set([1, total, current - 1, current, current + 1])
      if (current <= 3) {
        pages.add(2)
        pages.add(3)
        pages.add(4)
      }
      if (current >= total - 2) {
        pages.add(total - 1)
        pages.add(total - 2)
        pages.add(total - 3)
      }
      const sorted = Array.from(pages).filter((page) => page >= 1 && page <= total).sort((a, b) => a - b)
      const result = []
      let previous = 0
      for (const page of sorted) {
        if (previous && page - previous > 1) result.push(`gap-${page}`)
        result.push(page)
        previous = page
      }
      return result
    }

    function Pagination({ page, pageCount, total, pageSize, onPage, onPageSizeChange, lang, t }) {
      if (total <= 0) return null
      const window = buildPageWindow(page, pageCount)
      return h(
        'div',
        { className: 'ldv-pagination' },
        h(
          'div',
          { className: 'ldv-pagination-info' },
          h('span', null, t('resultCount', { count: formatNumber(total, lang) })),
          h('span', { className: 'ldv-pagination-dot' }, '·'),
          h('span', null, t('pageInfo', { page, pages: pageCount })),
        ),
        h(
          'div',
          { className: 'ldv-pagination-controls' },
          h(
            'label',
            { className: 'ldv-page-size' },
            h('span', null, t('pageSize')),
            h(
              'select',
              {
                className: 'ldv-select compact',
                value: pageSize,
                onChange: (event) => onPageSizeChange(Number(event.target.value)),
              },
              PAGE_SIZE_OPTIONS.map((size) => h('option', { key: size, value: size }, t('perPage', { size }))),
            ),
          ),
          h(
            'button',
            { type: 'button', className: 'ldv-btn tiny', disabled: page <= 1, onClick: () => onPage(page - 1) },
            t('prev'),
          ),
          h(
            'div',
            { className: 'ldv-page-buttons' },
            window.map((item) => (
              typeof item === 'number'
                ? h(
                    'button',
                    {
                      key: item,
                      type: 'button',
                      className: 'ldv-page-btn' + (item === page ? ' active' : ''),
                      'aria-current': item === page ? 'page' : undefined,
                      title: t('a11yPage', { page: item }),
                      onClick: () => onPage(item),
                    },
                    item,
                  )
                : h('span', { key: item, className: 'ldv-page-gap' }, '…')
            )),
          ),
          h(
            'button',
            { type: 'button', className: 'ldv-btn tiny', disabled: page >= pageCount, onClick: () => onPage(page + 1) },
            t('next'),
          ),
        ),
      )
    }

    function QueryCard({
      t,
      lang,
      queryType,
      queryValue,
      pageSize,
      page,
      result,
      querying,
      queryError,
      onTypeChange,
      onValueChange,
      onPageSizeChange,
      onPage,
      onQuery,
    }) {
      const entries = result && Array.isArray(result.entries) ? result.entries : []
      const total = result ? (Number.isFinite(result.total) ? result.total : entries.length) : 0
      const pageCount = entries.length > 0 ? Math.max(1, Math.ceil(entries.length / pageSize)) : 1
      const pageEntries = entries.slice((page - 1) * pageSize, (page - 1) * pageSize + pageSize)
      const placeholder = queryType === 'email'
        ? t('queryPlaceholderEmail')
        : queryType === 'mobile'
          ? t('queryPlaceholderMobile')
          : t('queryPlaceholderAccount')

      return h(
        'section',
        { className: 'ldv-card ldv-query-card' },
        h(
          'div',
          { className: 'ldv-card-head' },
          h(
            'div',
            null,
            h('h2', null, t('queryTitle')),
            h('p', { className: 'ldv-card-sub' }, t('querySubtitle')),
          ),
          h('span', { className: 'ldv-query-badge' }, h(SearchGlyph, { size: 13 }), t('exactMatch')),
        ),
        h(
          'form',
          {
            className: 'ldv-query-form',
            onSubmit: (event) => {
              event.preventDefault()
              onQuery()
            },
          },
          h(
            'label',
            { className: 'ldv-query-field' },
            h('span', { className: 'ldv-label' }, t('queryType')),
            h(
              'select',
              {
                className: 'ldv-select ldv-query-type',
                value: queryType,
                onChange: (event) => onTypeChange(event.target.value),
                disabled: querying,
              },
              h('option', { value: 'account' }, t('account')),
              h('option', { value: 'email' }, t('email')),
              h('option', { value: 'mobile' }, t('mobile')),
            ),
          ),
          h(
            'label',
            { className: 'ldv-query-field ldv-query-grow' },
            h('span', { className: 'ldv-label' }, t('search')),
            h('input', {
              className: 'ldv-input',
              value: queryValue,
              placeholder,
              spellCheck: false,
              autoComplete: 'off',
              disabled: querying,
              onChange: (event) => onValueChange(event.target.value),
            }),
          ),
          h(
            'button',
            {
              type: 'submit',
              className: 'ldv-btn primary ldv-query-submit',
              disabled: querying || queryValue.trim().length === 0,
              title: t('a11yQuery'),
            },
            querying ? h('span', { className: 'ldv-spinner small' }) : h(SearchGlyph),
            querying ? t('searching') : t('search'),
          ),
        ),
        h(
          'div',
          { className: 'ldv-query-meta' },
          h('span', null, t('exactMatch')),
          h('span', { className: 'ldv-query-meta-dot' }, '·'),
          h('span', null, t('maxResults', { max: MAX_RESULTS })),
          h('span', { className: 'ldv-query-meta-dot' }, '·'),
          h('span', null, t('queryNote')),
        ),
        queryError ? h(ErrorLine, { error: queryError, t }) : null,
        result
          ? h(
              'div',
              { className: 'ldv-results' },
              h(
                'div',
                { className: 'ldv-resultbar' },
                h(
                  'div',
                  { className: 'ldv-result-summary', 'aria-live': 'polite' },
                  h('strong', null, t('resultCount', { count: formatNumber(total, lang) })),
                  h('span', { className: 'ldv-result-server', title: result.server }, t('serverLabel', { server: result.server })),
                ),
                h(
                  'div',
                  { className: 'ldv-result-extra' },
                  result.truncated ? h('span', { className: 'ldv-truncated' }, t('truncated', { max: MAX_RESULTS })) : null,
                  h('span', { className: 'ldv-duration' }, t('tookTime', { ms: result.durationMs })),
                ),
              ),
              pageEntries.length > 0
                ? h(
                    'div',
                    { className: 'ldv-table-wrap' },
                    h(
                      'table',
                      { className: 'ldv-table' },
                      h(
                        'thead',
                        null,
                        h(
                          'tr',
                          null,
                          h('th', null, t('colAccount')),
                          h('th', null, t('colEmail')),
                          h('th', null, t('colMobile')),
                          h('th', null, t('colDepartment')),
                          h('th', null, t('colEnabled')),
                          h('th', null, t('colLock')),
                          h('th', null, t('colAccountExpiry')),
                          h('th', null, t('colPassword')),
                        ),
                      ),
                      h('tbody', null, pageEntries.map((entry) => h(UserRow, {
                        key: entry.dn || entry.account,
                        entry,
                        t,
                        lang,
                      }))),
                    ),
                  )
                : h(EmptyState, {
                    icon: h(SearchGlyph, { size: 24 }),
                    title: t('noResultsTitle'),
                    body: t('noResultsBody'),
                  }),
              h(Pagination, {
                page,
                pageCount,
                total,
                pageSize,
                onPage,
                onPageSizeChange,
                lang,
                t,
              }),
            )
          : h(EmptyState, {
              icon: h(ServerGlyph, { size: 24 }),
              title: t('initialTitle'),
              body: t('initialBody'),
            }),
      )
    }

    class Boundary extends React.Component {
      constructor(props) {
        super(props)
        this.state = { failed: false }
      }

      static getDerivedStateFromError() {
        return { failed: true }
      }

      render() {
        if (this.state.failed) {
          const t = this.props.t || ((key) => key)
          return h(
            'div',
            { className: 'ldv-page' },
            h('style', null, CSS),
            h(
              'div',
              { className: 'ldv-shell' },
              h(
                'section',
                { className: 'ldv-card' },
                h(EmptyState, { icon: h(AlertGlyph, { size: 24 }), title: t('errorRender') }),
              ),
            ),
          )
        }
        return this.props.children
      }
    }

    function LdapApp({ ctx, t }) {
      useLocaleTick(ctx)
      const activeLocale = String(ctx.locale.getSnapshot().active || 'zh-CN')
      const lang = isZh(activeLocale) ? 'zh-CN' : 'en-US'

      const [loading, setLoading] = useState(true)
      const [config, setConfig] = useState(null)
      const [password, setPassword] = useState({ configured: false, source: null })
      const [loadError, setLoadError] = useState(null)
      const [editing, setEditing] = useState(false)
      const [draft, setDraft] = useState(null)
      const [saving, setSaving] = useState(false)
      const [formError, setFormError] = useState(null)
      const [showPassword, setShowPassword] = useState(false)
      const [configSaved, setConfigSaved] = useState(false)

      const [queryType, setQueryType] = useState('account')
      const [queryValue, setQueryValue] = useState('')
      const [pageSize, setPageSize] = useState(20)
      const [page, setPage] = useState(1)
      const [querying, setQuerying] = useState(false)
      const [result, setResult] = useState(null)
      const [queryError, setQueryError] = useState(null)

      const savedTimer = useRef(null)
      const configRef = useRef(null)

      useEffect(() => {
        configRef.current = config
      }, [config])

      useEffect(() => () => {
        if (savedTimer.current) window.clearTimeout(savedTimer.current)
      }, [])

      const showSaved = () => {
        setConfigSaved(true)
        if (savedTimer.current) window.clearTimeout(savedTimer.current)
        savedTimer.current = window.setTimeout(() => setConfigSaved(false), 2200)
      }

      const loadConfig = async () => {
        setLoading(true)
        setLoadError(null)
        try {
          const payload = await request('/config')
          setConfig(payload.config)
          setPassword(payload.password || { configured: false, source: null })
        } catch (error) {
          setConfig(null)
          setLoadError(error)
        } finally {
          setLoading(false)
        }
      }

      useEffect(() => {
        loadConfig()
        // The page loads once; subsequent locale changes only affect labels.
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, [])

      const startEdit = () => {
        const current = configRef.current
        if (!current) return
        setDraft({
          host: current.host,
          port: String(current.port),
          baseDn: current.baseDn,
          bindDn: current.bindDn,
          password: '',
        })
        setFormError(null)
        setShowPassword(false)
        setEditing(true)
      }

      const cancelEdit = () => {
        setDraft(null)
        setFormError(null)
        setShowPassword(false)
        setEditing(false)
      }

      const changeDraft = (field, value) => {
        setDraft((current) => (current ? { ...current, [field]: value } : current))
        setFormError(null)
      }

      const saveConfig = async () => {
        if (!draft) return
        const host = draft.host.trim()
        const baseDn = draft.baseDn.trim()
        const port = Number(draft.port)
        if (!host) {
          setFormError({ code: 'VALIDATION', message: t('host') })
          return
        }
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          setFormError({ code: 'VALIDATION', message: t('port') })
          return
        }
        if (!baseDn) {
          setFormError({ code: 'VALIDATION', message: t('baseDn') })
          return
        }
        setSaving(true)
        setFormError(null)
        try {
          const body = {
            host,
            port,
            baseDn,
            bindDn: draft.bindDn.trim(),
          }
          if (draft.password) body.password = draft.password
          const payload = await request('/config', { method: 'PUT', body: JSON.stringify(body) })
          setConfig(payload.config)
          setPassword(payload.password || { configured: false, source: null })
          setEditing(false)
          setDraft(null)
          setShowPassword(false)
          showSaved()
        } catch (error) {
          setFormError(error)
        } finally {
          setSaving(false)
        }
      }

      const runQuery = async () => {
        const value = queryValue.trim()
        if (!value) {
          setQueryError({ code: 'VALIDATION', message: t('queryValueRequired') })
          return
        }
        setQuerying(true)
        setQueryError(null)
        try {
          const payload = await request('/query', {
            method: 'POST',
            body: JSON.stringify({ type: queryType, value }),
          })
          setResult(payload)
          setPage(1)
        } catch (error) {
          setResult(null)
          setQueryError(error)
        } finally {
          setQuerying(false)
        }
      }

      const pageCount = result ? Math.max(1, Math.ceil(result.entries.length / pageSize)) : 1
      useEffect(() => {
        setPage((current) => Math.min(Math.max(1, current), pageCount))
      }, [pageCount])

      const changePageSize = (size) => {
        setPageSize(size)
        setPage(1)
      }

      return h(
        'div',
        { className: 'ldv-page' },
        h('style', null, CSS),
        h(
          'div',
          { className: 'ldv-shell' },
          h(
            'header',
            { className: 'ldv-hero' },
            h('div', { className: 'ldv-hero-mark' }, h(ServerGlyph, { size: 24 })),
            h(
              'div',
              { className: 'ldv-hero-text' },
              h(
                'div',
                { className: 'ldv-hero-title-row' },
                h('h1', null, t('appTitle')),
                h('span', { className: 'ldv-pill' }, h('span', { className: 'ldv-dot' }), t('readOnly')),
              ),
              h('p', null, t('appSubtitle')),
            ),
          ),
          h(ConfigCard, {
            t,
            config,
            password,
            loading,
            loadError,
            editing,
            draft,
            saving,
            formError,
            showPassword,
            configSaved,
            onRetry: loadConfig,
            onStartEdit: startEdit,
            onCancel: cancelEdit,
            onSave: saveConfig,
            onDraftChange: changeDraft,
            onTogglePassword: () => setShowPassword((value) => !value),
          }),
          h(QueryCard, {
            t,
            lang,
            queryType,
            queryValue,
            pageSize,
            page,
            result,
            querying,
            queryError,
            onTypeChange: (value) => {
              setQueryType(value)
              setQueryError(null)
            },
            onValueChange: (value) => {
              setQueryValue(value)
              setQueryError(null)
            },
            onPageSizeChange: changePageSize,
            onPage: (nextPage) => setPage(Math.min(Math.max(1, nextPage), pageCount)),
            onQuery: runQuery,
          }),
          h(
            'footer',
            { className: 'ldv-footer' },
            h('span', null, t('queryNote')),
            h('span', { className: 'ldv-footer-version' }, 'LDAP Viewer · v1.0.0'),
          ),
        ),
      )
    }

    const CSS = `
.ldv-page {
  --ldv-line: var(--dsw-alias-border-l1);
  --ldv-line-strong: var(--dsw-alias-border-l2);
  --ldv-fg: var(--dsw-alias-label-primary);
  --ldv-dim: var(--dsw-alias-label-secondary);
  --ldv-card: var(--dsw-alias-bg-layer-1);
  --ldv-nested: var(--dsw-alias-bg-layer-2);
  --ldv-success: var(--dsw-alias-state-success-primary);
  --ldv-danger: var(--dsw-alias-state-error-primary);
  --ldv-warn: var(--dsw-alias-state-warn-primary);
  height: 100%;
  min-height: 0;
  overflow: auto;
  box-sizing: border-box;
  background: var(--dsw-alias-bg-base);
  color: var(--ldv-fg);
  padding: 26px clamp(16px, 4vw, 44px) 38px;
  font-size: 13px;
  line-height: 1.55;
}
.ldv-page *, .ldv-page *::before, .ldv-page *::after { box-sizing: border-box; }
.ldv-page button, .ldv-page input, .ldv-page select { font: inherit; }
.ldv-shell { width: 100%; max-width: 1280px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
.ldv-hero { display: flex; align-items: center; gap: 14px; padding: 2px 2px 4px; }
.ldv-hero-mark {
  width: 46px; height: 46px; flex: 0 0 46px; display: grid; place-items: center;
  border-radius: 13px; color: var(--dsw-alias-brand-primary);
  background: var(--ldv-card); border: 1px solid var(--ldv-line);
}
.ldv-hero-text { min-width: 0; }
.ldv-hero-title-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.ldv-hero h1 { margin: 0; font-size: 22px; line-height: 1.25; font-weight: 650; letter-spacing: -.015em; }
.ldv-hero p { margin: 4px 0 0; color: var(--ldv-dim); font-size: 12.5px; line-height: 1.55; }
.ldv-pill {
  display: inline-flex; align-items: center; gap: 5px; height: 22px; padding: 0 8px;
  border-radius: 999px; border: 1px solid var(--ldv-line);
  background: var(--ldv-card); color: var(--ldv-dim);
  font-size: 10.5px; font-weight: 500; white-space: nowrap;
}
.ldv-dot { width: 5px; height: 5px; border-radius: 50%; background: currentColor; flex: 0 0 auto; }
.ldv-pill .ldv-dot { background: var(--ldv-success); }
.ldv-card {
  background: var(--ldv-card);
  border: 1px solid var(--ldv-line);
  border-radius: 14px;
  padding: 18px;
}
.ldv-card-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; margin-bottom: 15px; }
.ldv-title-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.ldv-card h2 { margin: 0; font-size: 14px; line-height: 1.35; font-weight: 650; letter-spacing: -.005em; }
.ldv-card-sub { margin: 4px 0 0; color: var(--ldv-dim); font-size: 11.5px; line-height: 1.5; }
.ldv-readonly {
  display: inline-flex; align-items: center; height: 18px; padding: 0 6px; border-radius: 5px;
  background: var(--ldv-nested); color: var(--ldv-dim);
  font-size: 10px; font-weight: 500; letter-spacing: .01em;
}
.ldv-saved {
  display: inline-flex; align-items: center; height: 18px; padding: 0 7px; border-radius: 5px;
  background: color-mix(in srgb, var(--ldv-success) 12%, transparent);
  color: var(--ldv-success); font-size: 10px; font-weight: 600;
  animation: ldv-fade-in .16s ease-out;
}
.ldv-actions { display: flex; align-items: center; gap: 8px; flex: 0 0 auto; }
.ldv-btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  height: 32px; padding: 0 12px; border-radius: 8px;
  border: 1px solid var(--ldv-line);
  background: var(--ldv-nested);
  color: var(--ldv-fg);
  font-size: 12px; font-weight: 550; line-height: 1;
  cursor: pointer; white-space: nowrap;
  transition: background .14s ease, border-color .14s ease, filter .14s ease, opacity .14s ease;
}
.ldv-btn:hover:not(:disabled) { background: var(--ldv-card); border-color: var(--ldv-line-strong); }
.ldv-btn.primary {
  background: var(--dsw-alias-brand-primary);
  border-color: var(--dsw-alias-brand-primary);
  color: var(--dsw-alias-bg-base);
}
.ldv-btn.primary:hover:not(:disabled) { filter: brightness(1.06); background: var(--dsw-alias-brand-primary); border-color: var(--dsw-alias-brand-primary); }
.ldv-btn.tiny { height: 28px; padding: 0 9px; border-radius: 7px; font-size: 11px; }
.ldv-btn:disabled { opacity: .42; cursor: not-allowed; }
.ldv-btn:focus-visible, .ldv-page-btn:focus-visible, .ldv-eye:focus-visible, .ldv-select:focus-visible, .ldv-input:focus-visible {
  outline: 2px solid var(--dsw-alias-brand-primary); outline-offset: 1px;
}
.ldv-info-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.ldv-info {
  min-width: 0; padding: 9px 11px 10px; border-radius: 9px;
  background: var(--ldv-nested); border: 1px solid var(--ldv-line);
}
.ldv-info.wide { grid-column: span 2; }
.ldv-info-label { margin-bottom: 5px; color: var(--ldv-dim); font-size: 10.5px; font-weight: 500; }
.ldv-info-value { display: flex; align-items: center; gap: 8px; min-width: 0; font-size: 12.5px; font-weight: 550; }
.ldv-info-text { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ldv-info-value.mono .ldv-info-text { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11.5px; letter-spacing: -.01em; }
.ldv-server-value { display: inline-flex; align-items: center; gap: 8px; min-width: 0; }
.ldv-mini-tag {
  display: inline-flex; align-items: center; height: 17px; padding: 0 6px; border-radius: 4px;
  background: var(--ldv-card); border: 1px solid var(--ldv-line); color: var(--ldv-dim);
  font-size: 9.5px; font-weight: 600; letter-spacing: .02em;
}
.ldv-inline-status { display: inline-flex; align-items: center; gap: 5px; white-space: nowrap; }
.ldv-inline-status.success { color: var(--ldv-success); }
.ldv-inline-status.danger { color: var(--ldv-danger); }
.ldv-source { margin-left: 5px; padding-left: 7px; border-left: 1px solid var(--ldv-line); color: var(--ldv-dim); font-size: 10px; font-weight: 400; }
.ldv-form-grid { display: grid; grid-template-columns: minmax(0, 1.5fr) minmax(130px, .5fr); gap: 14px; }
.ldv-field { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.ldv-field.full { grid-column: 1 / -1; }
.ldv-field label, .ldv-label { color: var(--ldv-dim); font-size: 11px; font-weight: 500; }
.ldv-input {
  width: 100%; height: 36px; padding: 0 10px; border-radius: 8px;
  border: 1px solid var(--ldv-line);
  background: var(--ldv-nested);
  color: var(--ldv-fg);
  font-size: 12.5px; line-height: 1;
  outline: none;
}
.ldv-input.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11.5px; }
.ldv-input:focus { border-color: var(--dsw-alias-brand-primary); }
.ldv-input::placeholder { color: var(--ldv-dim); opacity: .72; }
.ldv-select {
  height: 36px; padding: 0 28px 0 10px; border-radius: 8px;
  border: 1px solid var(--ldv-line);
  background: var(--ldv-nested);
  color: var(--ldv-fg);
  font-size: 12.5px; outline: none; cursor: pointer;
}
.ldv-select.compact { height: 28px; padding: 0 24px 0 8px; border-radius: 7px; font-size: 11px; }
.ldv-select:focus { border-color: var(--dsw-alias-brand-primary); }
.ldv-password-wrap { position: relative; display: flex; }
.ldv-password-wrap .ldv-input { padding-right: 38px; }
.ldv-eye {
  position: absolute; right: 4px; top: 50%; transform: translateY(-50%);
  display: inline-grid; place-items: center; width: 27px; height: 27px; padding: 0;
  border: 0; border-radius: 7px; background: transparent; color: var(--ldv-dim);
  cursor: pointer; flex: 0 0 auto;
}
.ldv-eye:hover { background: var(--ldv-card); color: var(--ldv-fg); }
.ldv-hint { margin: 0; color: var(--ldv-dim); font-size: 10.5px; line-height: 1.45; }
.ldv-card-foot { margin-top: 13px; padding-top: 12px; border-top: 1px solid var(--ldv-line); color: var(--ldv-dim); font-size: 10.5px; line-height: 1.45; }
.ldv-warning {
  display: flex; align-items: flex-start; gap: 7px; margin-top: 12px;
  padding: 9px 11px; border: 1px solid color-mix(in srgb, var(--ldv-warn) 32%, var(--ldv-line));
  border-radius: 8px; background: color-mix(in srgb, var(--ldv-warn) 8%, transparent);
  color: var(--ldv-warn); font-size: 11px; line-height: 1.5;
}
.ldv-warning svg { flex: 0 0 auto; margin-top: 1px; }
.ldv-error {
  display: flex; align-items: flex-start; gap: 7px; margin-top: 12px;
  color: var(--ldv-danger); font-size: 11.5px; line-height: 1.5;
}
.ldv-error svg { flex: 0 0 auto; margin-top: 1px; }
.ldv-error-text { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.ldv-error-detail { color: var(--ldv-dim); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 10.5px; line-height: 1.45; word-break: break-word; }
.ldv-loading { display: flex; align-items: center; gap: 9px; color: var(--ldv-dim); font-size: 12px; }
.ldv-spinner {
  width: 15px; height: 15px; border-radius: 50%;
  border: 2px solid color-mix(in srgb, var(--dsw-alias-brand-primary) 25%, transparent);
  border-top-color: var(--dsw-alias-brand-primary);
  animation: ldv-spin .7s linear infinite;
}
.ldv-spinner.small { width: 12px; height: 12px; border-width: 1.8px; }
.ldv-query-form { display: flex; align-items: flex-end; gap: 9px; flex-wrap: wrap; }
.ldv-query-field { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.ldv-query-field .ldv-label { display: block; }
.ldv-query-type { width: 132px; }
.ldv-query-grow { flex: 1 1 280px; }
.ldv-query-submit { height: 36px; min-width: 96px; flex: 0 0 auto; }
.ldv-query-badge {
  display: inline-flex; align-items: center; gap: 5px; height: 22px; padding: 0 8px;
  border-radius: 999px; border: 1px solid var(--ldv-line); background: var(--ldv-nested);
  color: var(--ldv-dim); font-size: 10.5px; white-space: nowrap;
}
.ldv-query-meta { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 10px; color: var(--ldv-dim); font-size: 10px; }
.ldv-query-meta-dot { opacity: .5; }
.ldv-results { margin-top: 16px; }
.ldv-resultbar { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; flex-wrap: wrap; margin-bottom: 10px; }
.ldv-result-summary { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; min-width: 0; }
.ldv-result-summary strong { font-size: 13px; font-weight: 650; }
.ldv-result-server { color: var(--ldv-dim); font-size: 10.5px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ldv-result-extra { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.ldv-truncated { color: var(--ldv-warn); font-size: 10.5px; }
.ldv-duration { color: var(--ldv-dim); font-size: 10px; font-variant-numeric: tabular-nums; white-space: nowrap; }
.ldv-table-wrap { border: 1px solid var(--ldv-line); border-radius: 10px; overflow: auto; }
.ldv-table { width: 100%; border-collapse: collapse; min-width: 1180px; font-size: 12px; }
.ldv-table th {
  position: sticky; top: 0; z-index: 1;
  padding: 9px 11px; border-bottom: 1px solid var(--ldv-line);
  background: var(--ldv-nested); color: var(--ldv-dim);
  font-size: 10.5px; font-weight: 600; text-align: left; white-space: nowrap; letter-spacing: .015em;
}
.ldv-table td { padding: 10px 11px; border-bottom: 1px solid var(--ldv-line); vertical-align: middle; }
.ldv-table tbody tr:last-child td { border-bottom: 0; }
.ldv-table tbody tr:hover { background: color-mix(in srgb, var(--ldv-nested) 55%, transparent); }
.ldv-account-cell { display: flex; flex-direction: column; gap: 1px; min-width: 0; max-width: 230px; }
.ldv-account { font-size: 12.5px; font-weight: 650; color: var(--ldv-fg); overflow-wrap: anywhere; }
.ldv-name { color: var(--ldv-dim); font-size: 10.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ldv-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11.5px; }
.ldv-truncate { display: inline-block; max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom; }
.ldv-muted { color: var(--ldv-dim); opacity: .72; }
.ldv-cell-stack { display: flex; flex-direction: column; gap: 3px; align-items: flex-start; min-width: 0; }
.ldv-badge {
  display: inline-flex; align-items: center; gap: 5px; height: 21px; padding: 0 8px;
  border-radius: 999px; border: 1px solid var(--ldv-line); background: var(--ldv-nested);
  color: var(--ldv-dim); font-size: 10.5px; font-weight: 500; white-space: nowrap; line-height: 1;
}
.ldv-badge .ldv-dot { width: 5px; height: 5px; }
.ldv-badge.success { color: var(--ldv-success); border-color: color-mix(in srgb, var(--ldv-success) 32%, var(--ldv-line)); background: color-mix(in srgb, var(--ldv-success) 8%, transparent); }
.ldv-badge.danger { color: var(--ldv-danger); border-color: color-mix(in srgb, var(--ldv-danger) 32%, var(--ldv-line)); background: color-mix(in srgb, var(--ldv-danger) 8%, transparent); }
.ldv-badge.warn { color: var(--ldv-warn); border-color: color-mix(in srgb, var(--ldv-warn) 34%, var(--ldv-line)); background: color-mix(in srgb, var(--ldv-warn) 8%, transparent); }
.ldv-badge.idle { color: var(--dsw-alias-state-idle-primary); }
.ldv-cell-note { color: var(--ldv-dim); font-size: 9.8px; line-height: 1.4; white-space: nowrap; max-width: 220px; overflow: hidden; text-overflow: ellipsis; }
.ldv-pagination { display: flex; align-items: center; justify-content: space-between; gap: 14px; flex-wrap: wrap; margin-top: 12px; color: var(--ldv-dim); font-size: 10.5px; }
.ldv-pagination-info { display: flex; align-items: center; gap: 5px; flex-wrap: wrap; }
.ldv-pagination-dot { opacity: .55; }
.ldv-pagination-controls { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; }
.ldv-page-size { display: inline-flex; align-items: center; gap: 5px; }
.ldv-page-buttons { display: flex; align-items: center; gap: 2px; }
.ldv-page-btn {
  min-width: 28px; height: 28px; padding: 0 6px; border-radius: 7px;
  border: 1px solid transparent; background: transparent; color: var(--ldv-dim);
  font-size: 11px; cursor: pointer; font-variant-numeric: tabular-nums;
}
.ldv-page-btn:hover { background: var(--ldv-nested); color: var(--ldv-fg); }
.ldv-page-btn.active { background: var(--ldv-nested); border-color: var(--ldv-line-strong); color: var(--ldv-fg); font-weight: 650; }
.ldv-page-gap { min-width: 20px; text-align: center; opacity: .55; }
.ldv-empty { text-align: center; padding: 32px 18px 34px; color: var(--ldv-dim); }
.ldv-empty-icon {
  width: 44px; height: 44px; margin: 0 auto 10px; display: grid; place-items: center;
  border-radius: 12px; background: var(--ldv-nested); border: 1px solid var(--ldv-line); color: var(--ldv-dim);
}
.ldv-empty h3 { margin: 0; color: var(--ldv-fg); font-size: 13px; font-weight: 600; }
.ldv-empty p { margin: 4px 0 0; font-size: 11.5px; line-height: 1.55; }
.ldv-footer { display: flex; justify-content: space-between; gap: 14px; padding: 0 2px; color: var(--ldv-dim); font-size: 10px; }
.ldv-footer-version { opacity: .7; }
@keyframes ldv-spin { to { transform: rotate(360deg); } }
@keyframes ldv-fade-in { from { opacity: 0; transform: translateY(1px); } to { opacity: 1; transform: none; } }
@media (max-width: 880px) {
  .ldv-info-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .ldv-info.wide { grid-column: span 2; }
  .ldv-form-grid { grid-template-columns: 1fr; }
  .ldv-field.full { grid-column: auto; }
  .ldv-query-type { width: 112px; }
}
@media (max-width: 560px) {
  .ldv-page { padding: 18px 12px 28px; }
  .ldv-card { padding: 14px; border-radius: 12px; }
  .ldv-card-head { flex-direction: column; gap: 10px; }
  .ldv-actions { width: 100%; }
  .ldv-actions .ldv-btn { flex: 1; }
  .ldv-info-grid { grid-template-columns: 1fr; }
  .ldv-info.wide { grid-column: auto; }
  .ldv-hero { align-items: flex-start; }
  .ldv-hero h1 { font-size: 19px; }
  .ldv-query-form { align-items: stretch; }
  .ldv-query-type { width: 100%; }
  .ldv-query-grow { flex-basis: 100%; }
  .ldv-query-submit { width: 100%; }
  .ldv-pagination { align-items: flex-start; flex-direction: column; }
  .ldv-pagination-controls { width: 100%; }
  .ldv-footer { flex-direction: column; }
}
@media (prefers-reduced-motion: reduce) {
  .ldv-spinner, .ldv-saved { animation: none; }
  .ldv-page * { transition: none !important; }
}
`

    function apply(ctx) {
      const locale = (ctx.get && ctx.get('locale')) || ctx.locale
      const slots = (ctx.get && ctx.get('slots')) || ctx.slots
      if (!locale || !slots) {
        console.error('[ldap-viewer] locale or slots service is unavailable')
        return
      }

      ctx.effect(() => {
        const snapshot = locale.getSnapshot()
        const disposers = snapshot.locales.map((item) => (
          locale.register(NS, item.id, isZh(item.id) ? MESSAGES.zh : MESSAGES.en)
        ))
        return () => {
          for (const dispose of disposers) dispose()
        }
      }, 'ldap-viewer: dictionaries')

      const t = makeTranslator(ctx)

      function Page() {
        return h(Boundary, { t }, h(LdapApp, { ctx, t }))
      }

      ctx.effect(() => slots.inject('sidebar.panellist', () => slots.register({
        name: 'sidebar.panellist',
        id: PANEL_ID,
        order: 60,
        label: () => t('appTitle'),
      }, (props) => h(SidebarIcon, {
        size: (props && props.size) || 20,
        active: Boolean(props && props.active),
      }))), 'ldap-viewer: sidebar entry')

      ctx.effect(() => slots.inject('main', () => slots.register({
        name: 'main',
        key: PANEL_ID,
      }, Page)), 'ldap-viewer: main page')

      console.log('[ldap-viewer] client registered')
    }

    return {
      inject: ['slots', 'locale'],
      apply,
      __test: { MESSAGES, buildPageWindow, formatDate, errorCopy },
    }
  },
})
