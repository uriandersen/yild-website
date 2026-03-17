-- Run this in Supabase SQL Editor
-- https://supabase.com/dashboard/project/ibjwgqpoisuvsnrxafdc/sql
-- Creates tables and RPC functions for the full NDA access flow

-- ══════════════════════════════════════════
-- 1. Access requests table
-- ══════════════════════════════════════════

CREATE TABLE IF NOT EXISTS access_requests (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL,
  company text,
  status text NOT NULL DEFAULT 'pending',  -- pending, approved, rejected
  nda_accepted_at timestamptz NOT NULL DEFAULT now(),
  nda_version text NOT NULL DEFAULT 'v1.0',
  ip_address text,
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now(),
  reviewed_at timestamptz,
  reviewed_by text
);

-- RLS: block direct access from anon
ALTER TABLE access_requests ENABLE ROW LEVEL SECURITY;

-- ══════════════════════════════════════════
-- 2. Submit access request (anon-callable)
-- ══════════════════════════════════════════

CREATE OR REPLACE FUNCTION submit_access_request(
  p_name text,
  p_email text,
  p_company text DEFAULT NULL,
  p_ip_address text DEFAULT 'unknown',
  p_user_agent text DEFAULT 'unknown'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_id bigint;
BEGIN
  -- Check for duplicate pending request with same email
  IF EXISTS (SELECT 1 FROM access_requests WHERE email = p_email AND status = 'pending') THEN
    RETURN jsonb_build_object('ok', true, 'message', 'Request already submitted');
  END IF;

  INSERT INTO access_requests (name, email, company, ip_address, user_agent)
  VALUES (p_name, p_email, p_company, p_ip_address, p_user_agent)
  RETURNING id INTO v_id;

  RETURN jsonb_build_object('ok', true, 'id', v_id);
END;
$$;

GRANT EXECUTE ON FUNCTION submit_access_request(text, text, text, text, text) TO anon;

-- ══════════════════════════════════════════
-- 3. List pending requests (admin only via admin_key)
-- ══════════════════════════════════════════

CREATE OR REPLACE FUNCTION list_access_requests(p_admin_key text, p_status text DEFAULT 'pending')
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_admin record;
  v_rows jsonb;
BEGIN
  -- Verify admin key exists and is not revoked
  SELECT * INTO v_admin FROM access_keys WHERE key = p_admin_key AND NOT revoked;
  IF v_admin IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized');
  END IF;

  SELECT jsonb_agg(jsonb_build_object(
    'id', r.id,
    'name', r.name,
    'email', r.email,
    'company', r.company,
    'status', r.status,
    'nda_version', r.nda_version,
    'ip_address', r.ip_address,
    'created_at', r.created_at,
    'reviewed_at', r.reviewed_at
  ) ORDER BY r.created_at DESC)
  INTO v_rows
  FROM access_requests r
  WHERE r.status = p_status;

  RETURN jsonb_build_object('ok', true, 'requests', COALESCE(v_rows, '[]'::jsonb));
END;
$$;

GRANT EXECUTE ON FUNCTION list_access_requests(text, text) TO anon;

-- ══════════════════════════════════════════
-- 4. Approve / reject request (admin only)
-- ══════════════════════════════════════════

CREATE OR REPLACE FUNCTION review_access_request(
  p_admin_key text,
  p_request_id bigint,
  p_action text  -- 'approve' or 'reject'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_admin record;
  v_req record;
  v_new_key text;
BEGIN
  -- Verify admin
  SELECT * INTO v_admin FROM access_keys WHERE key = p_admin_key AND NOT revoked;
  IF v_admin IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized');
  END IF;

  -- Get request
  SELECT * INTO v_req FROM access_requests WHERE id = p_request_id;
  IF v_req IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Request not found');
  END IF;

  IF v_req.status != 'pending' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Request already reviewed');
  END IF;

  IF p_action = 'approve' THEN
    -- Generate unique access key: first 8 chars of name uppercase + random suffix
    v_new_key := upper(regexp_replace(split_part(v_req.name, ' ', 1), '[^A-Za-z]', '', 'g'))
                 || '-' || lpad(floor(random() * 10000)::text, 4, '0');

    -- Insert new access key
    INSERT INTO access_keys (key, name, revoked, expires_at)
    VALUES (v_new_key, v_req.name, false, now() + interval '90 days');

    -- Update request
    UPDATE access_requests
    SET status = 'approved', reviewed_at = now(), reviewed_by = v_admin.name
    WHERE id = p_request_id;

    RETURN jsonb_build_object('ok', true, 'status', 'approved', 'access_key', v_new_key, 'name', v_req.name, 'email', v_req.email);

  ELSIF p_action = 'reject' THEN
    UPDATE access_requests
    SET status = 'rejected', reviewed_at = now(), reviewed_by = v_admin.name
    WHERE id = p_request_id;

    RETURN jsonb_build_object('ok', true, 'status', 'rejected');
  ELSE
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid action. Use approve or reject.');
  END IF;
END;
$$;

GRANT EXECUTE ON FUNCTION review_access_request(text, bigint, text) TO anon;

-- ══════════════════════════════════════════
-- 5. Update validate_access_key to also log email
-- ══════════════════════════════════════════

CREATE OR REPLACE FUNCTION validate_access_key(p_key text, p_user_agent text DEFAULT 'unknown', p_ip_address text DEFAULT 'unknown')
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_row record;
BEGIN
  SELECT * INTO v_row FROM access_keys WHERE key = p_key;

  IF v_row IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid access key');
  END IF;

  IF v_row.revoked THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Access key has been revoked');
  END IF;

  IF v_row.expires_at IS NOT NULL AND v_row.expires_at < now() THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Access key has expired');
  END IF;

  INSERT INTO nda_log (access_key, ip_address, user_agent, nda_version, accepted)
  VALUES (p_key, p_ip_address, p_user_agent, 'v1.0', true);

  RETURN jsonb_build_object('ok', true, 'name', v_row.name);
END;
$$;

GRANT EXECUTE ON FUNCTION validate_access_key(text, text, text) TO anon;
