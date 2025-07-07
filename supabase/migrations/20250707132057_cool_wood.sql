/*
  # Add Trending Posts Functionality

  This migration adds functions to calculate and retrieve trending posts based on engagement metrics.

  ## Functions

  1. **calculate_trending_score**
     - Calculates a trending score based on likes, retweets, comments, and recency
     
  2. **get_trending_posts**
     - Returns posts ordered by trending score
     
  3. **refresh_trending_scores**
     - Updates trending scores for all posts (can be run periodically)

  ## Views

  - Create a view for trending posts with calculated scores
*/

-- Function to calculate trending score
CREATE OR REPLACE FUNCTION calculate_trending_score(
  like_count integer,
  retweet_count integer,
  comment_count integer,
  created_at timestamptz
) RETURNS numeric AS $$
DECLARE
  hours_since_creation numeric;
  engagement_score numeric;
  time_decay_factor numeric;
  trending_score numeric;
BEGIN
  -- Calculate hours since creation
  hours_since_creation := EXTRACT(EPOCH FROM (now() - created_at)) / 3600.0;
  
  -- Calculate engagement score (weighted)
  engagement_score := (like_count * 1.0) + (retweet_count * 2.0) + (comment_count * 3.0);
  
  -- Apply time decay (posts lose relevance over time)
  -- Using exponential decay with half-life of 24 hours
  time_decay_factor := power(0.5, hours_since_creation / 24.0);
  
  -- Calculate final trending score
  trending_score := engagement_score * time_decay_factor;
  
  RETURN trending_score;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Add trending_score column to posts table
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'posts' AND column_name = 'trending_score'
  ) THEN
    ALTER TABLE posts ADD COLUMN trending_score numeric DEFAULT 0;
  END IF;
END $$;

-- Add index for trending score
CREATE INDEX IF NOT EXISTS idx_posts_trending_score ON posts(trending_score DESC) WHERE status = 'approved';

-- Function to refresh trending scores
CREATE OR REPLACE FUNCTION refresh_trending_scores()
RETURNS void AS $$
BEGIN
  UPDATE posts 
  SET trending_score = calculate_trending_score(
    like_count, 
    retweet_count, 
    comment_count, 
    created_at
  )
  WHERE status = 'approved';
END;
$$ LANGUAGE plpgsql;

-- Function to get trending posts
CREATE OR REPLACE FUNCTION get_trending_posts(limit_param integer DEFAULT 50)
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
  original_post_id uuid,
  trending_score numeric
) AS $$
BEGIN
  -- Refresh trending scores for recent posts
  UPDATE posts 
  SET trending_score = calculate_trending_score(
    like_count, 
    retweet_count, 
    comment_count, 
    created_at
  )
  WHERE status = 'approved' 
    AND created_at > now() - interval '7 days';

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
    p.original_post_id,
    p.trending_score
  FROM posts p
  WHERE p.status = 'approved'
  ORDER BY p.trending_score DESC, p.created_at DESC
  LIMIT limit_param;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to update trending score when engagement changes
CREATE OR REPLACE FUNCTION update_trending_score_on_engagement()
RETURNS TRIGGER AS $$
BEGIN
  UPDATE posts 
  SET trending_score = calculate_trending_score(
    like_count, 
    retweet_count, 
    comment_count, 
    created_at
  )
  WHERE id = COALESCE(NEW.id, OLD.id);
  
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Create trigger for automatic trending score updates
DROP TRIGGER IF EXISTS trigger_update_trending_score ON posts;
CREATE TRIGGER trigger_update_trending_score
  AFTER UPDATE OF like_count, retweet_count, comment_count ON posts
  FOR EACH ROW EXECUTE FUNCTION update_trending_score_on_engagement();

-- Initialize trending scores for existing posts
SELECT refresh_trending_scores();