package login

// Exported wrappers so the generic Ask/transaction router (server package) can drive the
// login action (t=1) without duplicating prepareLogin/completeLogin. These mirror the HTTP
// handlers (HandlePreview/HandleApprove/HandleDecline) but return values instead of writing
// to a ResponseWriter.

// Preview resolves a login Ask (fetch bundle, verify site, mint pairwise) and returns the
// consent preview — the disclosures the site is requesting.
func (h *Handler) Preview(req StartLoginRequest) (*LoginPreviewResponse, error) {
	_, _, preview, err := h.prepareLogin(req)
	return preview, err
}

// Approve completes a login: prepare if not already pending, then sign the assertion and post
// it to the RP callback. Returns the RP's completion result.
func (h *Handler) Approve(req StartLoginRequest) (map[string]interface{}, error) {
	p, err := h.loadPending(req)
	if err != nil {
		bundle, rel, _, perr := h.prepareLogin(req)
		if perr != nil {
			return nil, perr
		}
		h.storePending(req, bundle, rel)
		p, err = h.loadPending(req)
		if err != nil {
			return nil, err
		}
	}
	return h.completeLogin(p)
}

// Decline drops a pending login session.
func (h *Handler) Decline(req StartLoginRequest) {
	h.Pending.Delete(req.SessionToken + "|" + req.RPSessionURL)
}
