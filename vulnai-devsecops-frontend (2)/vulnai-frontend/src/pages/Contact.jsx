import { useState } from "react";
import { Mail, MapPin, Clock, ArrowRight, CheckCircle2 } from "lucide-react";

const SUBJECTS = ["General question", "Report a bug", "Authorization / access request", "Partnership", "Other"];

export default function Contact() {
  const [form, setForm] = useState({ name: "", email: "", subject: SUBJECTS[0], message: "" });
  const [errors, setErrors] = useState({});
  const [submitted, setSubmitted] = useState(false);

  function update(field, value) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  function validate() {
    const next = {};
    if (!form.name.trim()) next.name = "Enter your name.";
    if (!form.email.trim()) next.email = "Enter your email.";
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) next.email = "Enter a valid email address.";
    if (!form.message.trim() || form.message.trim().length < 10) next.message = "Message should be at least 10 characters.";
    return next;
  }

  function handleSubmit(e) {
    e.preventDefault();
    const next = validate();
    setErrors(next);
    if (Object.keys(next).length === 0) {
      setSubmitted(true);
    }
  }

  return (
    <div>
      <section className="mx-auto max-w-4xl px-5 pb-8 pt-16 lg:px-8 lg:pt-24">
        <p className="kicker mb-4">Contact</p>
        <h1 className="font-display text-4xl font-medium leading-[1.15] text-text-main sm:text-5xl">
          Talk to the <span className="italic text-purple">team</span>.
        </h1>
        <p className="mt-6 max-w-xl text-base leading-relaxed text-text-secondary">
          Questions about the project, a bug to report, or an authorization request for a scan —
          send it over and we'll get back to you.
        </p>
      </section>

      <section className="mx-auto max-w-4xl px-5 pb-20 pt-8 lg:px-8 lg:pb-28">
        <div className="grid grid-cols-1 gap-10 border-t border-border pt-12 lg:grid-cols-5">
          {/* Form */}
          <div className="lg:col-span-3">
            {submitted ? (
              <div className="card flex flex-col items-start gap-3 p-8">
                <div className="flex h-12 w-12 items-center justify-center border border-[#4F7A5E]/35">
                  <CheckCircle2 size={22} strokeWidth={1.75} className="text-[#4F7A5E]" />
                </div>
                <h2 className="font-display text-xl font-medium text-text-main">Message received</h2>
                <p className="text-sm leading-relaxed text-text-secondary">
                  Thanks, {form.name.split(" ")[0]}. This is a demo build with no live backend, so
                  nothing was actually sent — but this is exactly the flow &amp; validation your
                  real endpoint would receive.
                </p>
                <button
                  onClick={() => {
                    setSubmitted(false);
                    setForm({ name: "", email: "", subject: SUBJECTS[0], message: "" });
                  }}
                  className="btn-outline mt-2 px-4 py-2 text-sm font-medium"
                >
                  Send another message
                </button>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-5" noValidate>
                <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
                  <Field
                    label="Full name"
                    value={form.name}
                    onChange={(v) => update("name", v)}
                    placeholder="Your name"
                    error={errors.name}
                  />
                  <Field
                    label="Email address"
                    type="email"
                    value={form.email}
                    onChange={(v) => update("email", v)}
                    placeholder="you@example.com"
                    error={errors.email}
                  />
                </div>

                <label className="block">
                  <span className="mb-1.5 block text-xs font-medium text-text-secondary">Subject</span>
                  <select
                    value={form.subject}
                    onChange={(e) => update("subject", e.target.value)}
                    className="w-full border border-border bg-bg-card px-3 py-2.5 text-sm text-text-main focus:border-purple focus:outline-none"
                  >
                    {SUBJECTS.map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </label>

                <label className="block">
                  <span className="mb-1.5 block text-xs font-medium text-text-secondary">Message</span>
                  <textarea
                    value={form.message}
                    onChange={(e) => update("message", e.target.value)}
                    placeholder="Tell us what's on your mind..."
                    rows={6}
                    className="w-full resize-none border border-border bg-bg-card px-3 py-2.5 text-sm text-text-main placeholder:text-text-muted focus:border-purple focus:outline-none"
                  />
                  {errors.message && <p className="mt-1.5 text-xs text-[#A83B42]">{errors.message}</p>}
                </label>

                <button
                  type="submit"
                  className="btn-signature flex items-center gap-2 px-6 py-3 text-sm font-semibold"
                >
                  Send message <ArrowRight size={15} />
                </button>
              </form>
            )}
          </div>

          {/* Info panel */}
          <div className="space-y-5 lg:col-span-2">
            <div className="card p-6">
              <p className="kicker mb-4">Reach us directly</p>
              <div className="space-y-4">
                <InfoRow icon={Mail} label="Email" value="team@vulnai-devsecops.dev" />
                <InfoRow icon={Clock} label="Response time" value="Within 2 business days" />
                <InfoRow icon={MapPin} label="Availability" value="Remote-first, async by default" />
              </div>
            </div>

            <div className="card p-6">
              <p className="kicker mb-3">Authorization requests</p>
              <p className="text-sm leading-relaxed text-text-secondary">
                Requesting a scan against a shared or third-party asset? Include proof of
                ownership or written permission with your message — we can't process access
                requests without it.
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

function Field({ label, value, onChange, placeholder, type = "text", error }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium text-text-secondary">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full border border-border bg-bg-card px-3 py-2.5 text-sm text-text-main placeholder:text-text-muted focus:border-purple focus:outline-none"
      />
      {error && <p className="mt-1.5 text-xs text-[#A83B42]">{error}</p>}
    </label>
  );
}

function InfoRow({ icon: Icon, label, value }) {
  return (
    <div className="flex items-start gap-3">
      <Icon size={15} strokeWidth={1.75} className="mt-0.5 shrink-0 text-blue-bright" />
      <div>
        <p className="text-xs text-text-muted">{label}</p>
        <p className="text-sm text-text-main">{value}</p>
      </div>
    </div>
  );
}
