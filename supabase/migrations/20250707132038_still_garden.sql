/*
  # Add User Following System

  This migration adds a proper user following system to enable the "Following" feed functionality.

  ## New Tables

  1. **user_follows**
     - `id` (uuid, primary key)
     - `follower_id` (text, references user_profiles.user_id)
     - `following_id` (text, references user_profiles.user_id)
     - `created_at` (timestamp)

  ## Security

  - Enable RLS on `user_follows` table
  - Add policies for users to manage their own follows
  - Add policies for viewing follow relationships

  ## Functions

  - Add function to update follower/following counts
  - Add triggers to maintain counts automatically
*/

-- Create user_follows table
CREATE TABLE IF NOT EXISTS user_follows (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  follower_id text NOT NULL,
  following_id text NOT NULL,
  created_at timestamptz DEFAULT now(),
  
  -- Constraints
  CONSTRAINT user_follows_follower_following_unique UNIQUE (follower_id, following_id),
  CONSTRAINT user_follows_no_self_follow CHECK (follower_id != following_id)
);

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_follows_follower_id ON user_follows(follower_id);
CREATE INDEX IF NOT EXISTS idx_user_follows_following_id ON user_follows(following_id);
CREATE INDEX IF NOT EXISTS idx_user_follows_created_at ON user_follows(created_at DESC);

-- Enable RLS
ALTER TABLE user_follows ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "Users can view all follow relationships" ON user_follows
  FOR SELECT TO public
  USING (true);

CREATE POLICY "Users can follow others" ON user_follows
  FOR INSERT TO public
  WITH CHECK (auth.uid()::text = follower_id);

CREATE POLICY "Users can unfollow others" ON user_follows
  FOR DELETE TO public
  USING (auth.uid()::text = follower_id);

-- Function to update follow counts
CREATE OR REPLACE FUNCTION update_follow_counts()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    -- Increase follower count for the user being followed
    UPDATE user_profiles 
    SET follower_count = follower_count + 1 
    WHERE user_id = NEW.following_id;
    
    -- Increase following count for the user doing the following
    UPDATE user_profiles 
    SET following_count = following_count + 1 
    WHERE user_id = NEW.follower_id;
    
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    -- Decrease follower count for the user being unfollowed
    UPDATE user_profiles 
    SET follower_count = GREATEST(follower_count - 1, 0) 
    WHERE user_id = OLD.following_id;
    
    -- Decrease following count for the user doing the unfollowing
    UPDATE user_profiles 
    SET following_count = GREATEST(following_count - 1, 0) 
    WHERE user_id = OLD.follower_id;
    
    RETURN OLD;
  END IF;
  
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for follow count updates
CREATE TRIGGER trigger_update_follow_counts
  AFTER INSERT OR DELETE ON user_follows
  FOR EACH ROW EXECUTE FUNCTION update_follow_counts();

-- Function to get posts from followed users
CREATE OR REPLACE FUNCTION get_following_posts(user_id_param text, limit_param integer DEFAULT 50)
RETURNS TABLE (
  id uuid,
  user_id text,
  username text,
  user_avatar text,
  content text,
  post_type text,
  media_url text,
  link_url text,
  link_title text,
  anime_id text,
  anime_title text,
  anime_image text,
  like_count integer,
  retweet_count integer,
  comment_count integer,
  created_at timestamptz,
  original_post_id uuid
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    p.id,
    p.user_id,
    p.username,
    p.user_avatar,
    p.content,
    p.post_type::text,
    p.media_url,
    p.link_url,
    p.link_title,
    p.anime_id,
    p.anime_title,
    p.anime_image,
    p.like_count,
    p.retweet_count,
    p.comment_count,
    p.created_at,
    p.original_post_id
  FROM posts p
  WHERE p.status = 'approved'
    AND (
      p.user_id = user_id_param OR
      p.user_id IN (
        SELECT uf.following_id 
        FROM user_follows uf 
        WHERE uf.follower_id = user_id_param
      )
    )
  ORDER BY p.created_at DESC
  LIMIT limit_param;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;