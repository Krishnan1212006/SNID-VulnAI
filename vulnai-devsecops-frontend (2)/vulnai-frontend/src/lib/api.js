const BASE_URL = `${import.meta.env.VITE_API_URL || "/api"}`;

function getHeaders() {
  const token = localStorage.getItem("token");
  const headers = {
    "Content-Type": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

async function request(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers: { ...getHeaders(), ...options.headers },
  });

  if (!response.ok) {
    let data;
    try {
      data = await response.json();
    } catch (err) {
      data = null;
    }
    if (response.status === 401) {
      localStorage.removeItem("token");
      window.dispatchEvent(new Event("auth:logout"));
    }
    const error = new Error(data?.detail || "HTTP Error");
    error.status = response.status;
    error.data = data;
    throw error;
  }

  let data;
  if (options.responseType === "blob") {
    data = await response.blob();
  } else {
    try {
      data = await response.json();
    } catch (err) {
      data = null;
    }
  }

  return { data, status: response.status, headers: response.headers };
}

const api = {
  get: (endpoint, options = {}) => request(endpoint, { method: "GET", ...options }),
  getBlob: (endpoint) => request(endpoint, { method: "GET", responseType: "blob" }),
  post: (endpoint, body, options = {}) => request(endpoint, { method: "POST", body: JSON.stringify(body), ...options }),
  put: (endpoint, body, options = {}) => request(endpoint, { method: "PUT", body: JSON.stringify(body), ...options }),
  patch: (endpoint, body, options = {}) => request(endpoint, { method: "PATCH", body: JSON.stringify(body), ...options }),
  delete: (endpoint, options = {}) => request(endpoint, { method: "DELETE", ...options }),
};

export default api;
