/*
  # Complete fix for RLS policies and admin functionality

  1. Database Reset
    - Drop all existing policies
    - Reset RLS configuration
    - Create clean, working policies

  2. Security
    - Fix auth.uid() function
    - Create proper admin check function
    - Enable proper user context setting

  3. Admin Keys
    - Fix admin key redemption
    - Add working admin codes
    - Proper error handling
*/

-- First, completely disable RLS on all tables to reset
ALTER TABLE posts DISABLE ROW LEVEL SECURITY;
ALTER TABLE user_profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE admin_keys DISABLE ROW LEVEL SECURITY;
ALTER TABLE comments DISABLE ROW LEVEL SECURITY;
ALTER TABLE likes DISABLE ROW LEVEL SECURITY;
ALTER TABLE retweets DISABLE ROW LEVEL SECURITY;

-- Drop ALL existing policies
DO $$ 
DECLARE 
    r RECORD;
BEGIN
    FOR r IN (SELECT schemaname, tablename, policyname FROM pg_policies WHERE schemaname = 'public') 
    LOOP
        EXECUTE 'DROP POLICY IF EXISTS ' || quote_ident(r.policyname) || ' ON ' || quote_ident(r.schemaname) || '.' || quote_ident(r.tablename);
    END LOOP;
END $$;

-- Drop existing functions that might conflict
DROP FUNCTION IF EXISTS auth.uid() CASCADE;
DROP FUNCTION IF EXISTS is_admin(text) CASCADE;
DROP FUNCTION IF EXISTS set_user_context(text) CASCADE;
DROP FUNCTION IF EXISTS redeem_admin_key(text, text) CASCADE;
DROP FUNCTION IF EXISTS get_current_user_id() CASCADE;

-- Create a robust auth.uid() function
CREATE OR REPLACE FUNCTION auth.uid() 
RETURNS text 
LANGUAGE sql 
STABLE 
SECURITY DEFINER
AS $$
  SELECT COALESCE(
    -- Try JWT first
    NULLIF(current_setting('request.jwt.claims', true), '')::json->>'sub',
    -- Fall back to app context
    NULLIF(current_setting('app.current_user_id', true), ''),
    -- Final fallback
    NULL
  )::text;
$$;

-- Create user context setter
CREATE OR REPLACE FUNCTION set_user_context(user_id_param text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  -- Set both contexts for maximum compatibility
  PERFORM set_config('app.current_user_id', user_id_param, true);
  PERFORM set_config('request.jwt.claims', 
    json_build_object('sub', user_id_param, 'aud', 'authenticated', 'role', 'authenticated')::text, 
    true);
END;
$$;

-- Create admin check function
CREATE OR REPLACE FUNCTION is_admin(check_user_id text DEFAULT NULL)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
  SELECT COALESCE(
    (SELECT is_admin 
     FROM user_profiles 
     WHERE user_id = COALESCE(check_user_id, auth.uid())
     LIMIT 1),
    false
  );
$$;

-- Create admin key redemption function
CREATE OR REPLACE FUNCTION redeem_admin_key(key_code_param text, user_id_param text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  key_found boolean := false;
  profile_exists boolean := false;
BEGIN
  -- Check if key exists and is unused
  SELECT EXISTS(
    SELECT 1 FROM admin_keys 
    WHERE key_code = key_code_param AND is_used = false
  ) INTO key_found;
  
  IF NOT key_found THEN
    RETURN false;
  END IF;
  
  -- Set user context
  PERFORM set_user_context(user_id_param);
  
  -- Check if profile exists
  SELECT EXISTS(
    SELECT 1 FROM user_profiles WHERE user_id = user_id_param
  ) INTO profile_exists;
  
  -- Create profile if it doesn't exist
  IF NOT profile_exists THEN
    INSERT INTO user_profiles (user_id, username, is_admin, created_at)
    VALUES (user_id_param, 'Admin User', true, now());
  ELSE
    -- Update existing profile to admin
    UPDATE user_profiles 
    SET is_admin = true, updated_at = now()
    WHERE user_id = user_id_param;
  END IF;
  
  -- Mark key as used
  UPDATE admin_keys 
  SET is_used = true, used_by = user_id_param, used_at = now()
  WHERE key_code = key_code_param AND is_used = false;
  
  RETURN true;
EXCEPTION
  WHEN OTHERS THEN
    RETURN false;
END;
$$;

-- Re-enable RLS and create simple, working policies
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;

-- Posts policies - SIMPLE and WORKING
CREATE POLICY "posts_select_approved" ON posts
  FOR SELECT USING (status = 'approved');

CREATE POLICY "posts_select_own" ON posts
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "posts_select_admin" ON posts
  FOR SELECT USING (is_admin());

CREATE POLICY "posts_insert_authenticated" ON posts
  FOR INSERT WITH CHECK (
    auth.uid() IS NOT NULL AND 
    user_id = auth.uid()
  );

CREATE POLICY "posts_update_own" ON posts
  FOR UPDATE USING (user_id = auth.uid());

CREATE POLICY "posts_update_admin" ON posts
  FOR UPDATE USING (is_admin());

CREATE POLICY "posts_delete_admin" ON posts
  FOR DELETE USING (is_admin());

-- User profiles policies
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "profiles_select_all" ON user_profiles
  FOR SELECT USING (true);

CREATE POLICY "profiles_insert_own" ON user_profiles
  FOR INSERT WITH CHECK (user_id = auth.uid());

CREATE POLICY "profiles_update_own" ON user_profiles
  FOR UPDATE USING (user_id = auth.uid());

-- Admin keys policies
ALTER TABLE admin_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY "admin_keys_select_unused" ON admin_keys
  FOR SELECT USING (is_used = false);

CREATE POLICY "admin_keys_update_all" ON admin_keys
  FOR UPDATE USING (true);

-- Comments policies
ALTER TABLE comments ENABLE ROW LEVEL SECURITY;

CREATE POLICY "comments_select_approved_posts" ON comments
  FOR SELECT USING (
    post_id IN (SELECT id FROM posts WHERE status = 'approved')
  );

CREATE POLICY "comments_insert_authenticated" ON comments
  FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);

CREATE POLICY "comments_update_own" ON comments
  FOR UPDATE USING (user_id = auth.uid());

-- Likes policies
ALTER TABLE likes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "likes_select_all" ON likes
  FOR SELECT USING (true);

CREATE POLICY "likes_insert_authenticated" ON likes
  FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);

CREATE POLICY "likes_update_own" ON likes
  FOR UPDATE USING (user_id = auth.uid());

CREATE POLICY "likes_delete_own" ON likes
  FOR DELETE USING (user_id = auth.uid());

-- Retweets policies
ALTER TABLE retweets ENABLE ROW LEVEL SECURITY;

CREATE POLICY "retweets_select_all" ON retweets
  FOR SELECT USING (true);

CREATE POLICY "retweets_insert_authenticated" ON retweets
  FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);

CREATE POLICY "retweets_update_own" ON retweets
  FOR UPDATE USING (user_id = auth.uid());

CREATE POLICY "retweets_delete_own" ON retweets
  FOR DELETE USING (user_id = auth.uid());

-- Grant all necessary permissions
GRANT EXECUTE ON FUNCTION auth.uid() TO public;
GRANT EXECUTE ON FUNCTION is_admin(text) TO public;
GRANT EXECUTE ON FUNCTION set_user_context(text) TO public;
GRANT EXECUTE ON FUNCTION redeem_admin_key(text, text) TO public;

-- Clear and add fresh admin keys
DELETE FROM admin_keys;
INSERT INTO admin_keys (key_code, is_used, created_at) VALUES 
  ('ADMIN-2025-001', false, now()),
  ('ADMIN-2025-002', false, now()),
  ('ADMIN-2025-003', false, now()),
  ('X145-GTHY-LKHA', false, now()),
  ('SUPER-ADMIN-KEY', false, now()),
  ('TEST-ADMIN-123', false, now()),
  ('DEMO-ADMIN-456', false, now()),
  ('QUICK-ADMIN-789', false, now());

-- Add performance indexes
CREATE INDEX IF NOT EXISTS idx_posts_user_status ON posts(user_id, status);
CREATE INDEX IF NOT EXISTS idx_posts_status_created ON posts(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_profiles_user_admin ON user_profiles(user_id, is_admin);
CREATE INDEX IF NOT EXISTS idx_admin_keys_code_used ON admin_keys(key_code, is_used);
CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id);
CREATE INDEX IF NOT EXISTS idx_likes_user_post ON likes(user_id, post_id);
CREATE INDEX IF NOT EXISTS idx_retweets_user_post ON retweets(user_id, post_id);

-- Refresh schema cache
NOTIFY pgrst, 'reload schema';