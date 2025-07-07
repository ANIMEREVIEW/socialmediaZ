/*
  # Fix RLS policies and admin system

  1. Database Fixes
    - Fix RLS policies for posts table
    - Update admin key system
    - Add proper user context handling
    - Fix post creation permissions

  2. Security Updates
    - Ensure proper RLS policies
    - Fix admin key validation
    - Update user context functions

  3. Performance Improvements
    - Add missing indexes
    - Optimize queries
*/

-- First, let's fix the RLS policies for posts table
DROP POLICY IF EXISTS "Users can create posts" ON posts;
DROP POLICY IF EXISTS "Users can update their own posts" ON posts;
DROP POLICY IF EXISTS "Anyone can view approved posts" ON posts;
DROP POLICY IF EXISTS "Admins can view all posts" ON posts;
DROP POLICY IF EXISTS "Admins can update all posts" ON posts;

-- Create better RLS policies for posts
CREATE POLICY "Anyone can view approved posts" ON posts
  FOR SELECT USING (status = 'approved');

CREATE POLICY "Users can view their own posts" ON posts
  FOR SELECT USING (user_id = (current_setting('app.current_user_id', true))::text);

CREATE POLICY "Admins can view all posts" ON posts
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM user_profiles 
      WHERE user_profiles.user_id = (current_setting('app.current_user_id', true))::text 
      AND user_profiles.is_admin = true
    )
  );

CREATE POLICY "Users can create posts" ON posts
  FOR INSERT WITH CHECK (user_id = (current_setting('app.current_user_id', true))::text);

CREATE POLICY "Users can update their own posts" ON posts
  FOR UPDATE USING (user_id = (current_setting('app.current_user_id', true))::text);

CREATE POLICY "Admins can update all posts" ON posts
  FOR UPDATE USING (
    EXISTS (
      SELECT 1 FROM user_profiles 
      WHERE user_profiles.user_id = (current_setting('app.current_user_id', true))::text 
      AND user_profiles.is_admin = true
    )
  );

CREATE POLICY "Admins can delete all posts" ON posts
  FOR DELETE USING (
    EXISTS (
      SELECT 1 FROM user_profiles 
      WHERE user_profiles.user_id = (current_setting('app.current_user_id', true))::text 
      AND user_profiles.is_admin = true
    )
  );

-- Fix admin_keys table policies
DROP POLICY IF EXISTS "Anyone can view unused admin keys" ON admin_keys;
DROP POLICY IF EXISTS "Anyone can update admin keys" ON admin_keys;

CREATE POLICY "Anyone can view unused admin keys" ON admin_keys
  FOR SELECT USING (is_used = false);

CREATE POLICY "Anyone can update admin keys for redemption" ON admin_keys
  FOR UPDATE USING (is_used = false);

-- Add some sample admin keys for testing
INSERT INTO admin_keys (key_code, is_used) VALUES 
  ('ADMIN-2025-001', false),
  ('ADMIN-2025-002', false),
  ('ADMIN-2025-003', false),
  ('X145-GTHY-LKHA', false),
  ('SUPER-ADMIN-KEY', false)
ON CONFLICT (key_code) DO NOTHING;

-- Create a function to safely set user context
CREATE OR REPLACE FUNCTION set_user_context(user_id_param text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  PERFORM set_config('app.current_user_id', user_id_param, true);
END;
$$;

-- Create a function to get current user context
CREATE OR REPLACE FUNCTION get_current_user_id()
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN current_setting('app.current_user_id', true);
END;
$$;

-- Add indexes for better performance
CREATE INDEX IF NOT EXISTS idx_posts_user_id_status ON posts(user_id, status);
CREATE INDEX IF NOT EXISTS idx_posts_status_created_at ON posts(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_profiles_user_id_admin ON user_profiles(user_id, is_admin);

-- Create a function to validate and redeem admin keys
CREATE OR REPLACE FUNCTION redeem_admin_key(key_code_param text, user_id_param text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  key_exists boolean := false;
BEGIN
  -- Check if key exists and is not used
  SELECT EXISTS(
    SELECT 1 FROM admin_keys 
    WHERE key_code = key_code_param AND is_used = false
  ) INTO key_exists;
  
  IF NOT key_exists THEN
    RETURN false;
  END IF;
  
  -- Mark key as used
  UPDATE admin_keys 
  SET is_used = true, used_by = user_id_param, used_at = now()
  WHERE key_code = key_code_param AND is_used = false;
  
  -- Make user admin
  UPDATE user_profiles 
  SET is_admin = true 
  WHERE user_id = user_id_param;
  
  RETURN true;
END;
$$;

-- Grant necessary permissions
GRANT EXECUTE ON FUNCTION set_user_context(text) TO public;
GRANT EXECUTE ON FUNCTION get_current_user_id() TO public;
GRANT EXECUTE ON FUNCTION redeem_admin_key(text, text) TO public;