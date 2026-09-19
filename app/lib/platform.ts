export type User = { id: string; name: string; email: string; role: 'ANALYST' | 'SENIOR_ANALYST' | 'ADMINISTRATOR' };
export class ApiError extends Error { constructor(message: string, public status: number) { super(message); } }
export async function api<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
  const csrf = typeof document !== 'undefined' ? document.cookie.split('; ').find(c => c.startsWith('mt_csrf='))?.split('=').slice(1).join('=') : '';
  const response = await fetch(`/api${path}`, { ...options, credentials: 'same-origin', cache: 'no-store', headers: {
    ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
    ...(csrf ? { 'X-CSRF-Token': decodeURIComponent(csrf) } : {}), ...options.headers,
  } });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const detail = typeof body.detail === 'string' ? body.detail : Array.isArray(body.detail) ? body.detail.map((d: { msg: string }) => d.msg).join('; ') : 'Service unavailable';
    throw new ApiError(detail, response.status);
  }
  return response.json();
}
export const post = <T = unknown>(path: string, body?: unknown) => api<T>(path, { method: 'POST', ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
