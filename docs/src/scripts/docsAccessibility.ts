// Supplement the template's drawer with keyboard focus and hidden-state handling.
const sidebar = document.querySelector<HTMLElement>("#docs-sidebar");
const toggle = document.querySelector<HTMLButtonElement>("[data-docs-sidebar-toggle]");
const closeButton = document.querySelector<HTMLButtonElement>("[data-sidebar-dismiss]");
const mobile = window.matchMedia("(max-width: 768px)");
let wasOpen = false;
function synchronizeSidebar() {
  if (!sidebar) return;
  const open = mobile.matches && sidebar.classList.contains("is-open");
  sidebar.inert = mobile.matches && !open;
  if (mobile.matches && !open) sidebar.setAttribute("aria-hidden", "true");
  else sidebar.removeAttribute("aria-hidden");
  if (open) { sidebar.setAttribute("role", "dialog"); sidebar.setAttribute("aria-modal", "true"); }
  else { sidebar.removeAttribute("role"); sidebar.removeAttribute("aria-modal"); }
  if (open && !wasOpen) closeButton?.focus();
  if (!open && wasOpen && mobile.matches) toggle?.focus();
  if (!mobile.matches) document.body.classList.remove("has-docs-sidebar-open");
  wasOpen = open;
}
if (sidebar) {
  new MutationObserver(synchronizeSidebar).observe(sidebar, { attributes: true, attributeFilter: ["class"] });
  mobile.addEventListener("change", synchronizeSidebar);
  closeButton?.addEventListener("click", () => {
    if (sidebar.classList.contains("is-open")) toggle?.click();
  });
  sidebar.addEventListener("keydown", (event) => {
    if (event.key !== "Tab" || !wasOpen) return;
    const items = [...sidebar.querySelectorAll<HTMLElement>("a[href], button:not([disabled])")].filter(item => item.getClientRects().length);
    const first = items[0], last = items.at(-1);
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  });
  synchronizeSidebar();
}
