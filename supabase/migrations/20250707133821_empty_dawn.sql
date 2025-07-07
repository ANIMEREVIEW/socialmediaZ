-- Add parent_id column to comments table for threaded comments
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'comments' AND column_name = 'parent_id'
  ) THEN
    ALTER TABLE comments ADD COLUMN parent_id uuid;
  END IF;
END $$;

-- Add foreign key constraint for parent_id
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints 
    WHERE constraint_name = 'comments_parent_id_fkey'
  ) THEN
    ALTER TABLE comments ADD CONSTRAINT comments_parent_id_fkey 
    FOREIGN KEY (parent_id) REFERENCES comments(id) ON DELETE CASCADE;
  END IF;
END $$;

-- Add index for parent_id
CREATE INDEX IF NOT EXISTS idx_comments_parent_id ON comments(parent_id);

-- Update RLS policies for comments to handle threaded comments
DROP POLICY IF EXISTS "Anyone can view comments on approved posts" ON comments;
CREATE POLICY "Anyone can view comments on approved posts" ON comments
  FOR SELECT TO public
  USING (
    post_id IN (
      SELECT id FROM posts WHERE status = 'approved'
    )
  );

-- Add policy for users to update their own comments
CREATE POLICY "Users can update their own comments" ON comments
  FOR UPDATE TO public
  USING (auth.uid()::text = user_id);

-- Add policy for users to delete their own comments
CREATE POLICY "Users can delete their own comments" ON comments
  FOR DELETE TO public
  USING (auth.uid()::text = user_id);

-- Function to get threaded comments for a post
CREATE OR REPLACE FUNCTION get_post_comments(post_id_param uuid)
RETURNS TABLE (
  id uuid,
  post_id uuid,
  user_id text,
  username text,
  user_avatar text,
  content text,
  like_count integer,
  parent_id uuid,
  created_at timestamptz,
  updated_at timestamptz
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    c.id,
    c.post_id,
    c.user_id,
    c.username,
    c.user_avatar,
    c.content,
    c.like_count,
    c.parent_id,
    c.created_at,
    c.updated_at
  FROM comments c
  WHERE c.post_id = post_id_param
  ORDER BY 
    CASE WHEN c.parent_id IS NULL THEN c.created_at ELSE NULL END DESC,
    c.created_at ASC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;