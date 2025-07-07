/*
  # Add notification triggers for user interactions

  1. Trigger Functions
    - Create notifications when posts are liked
    - Create notifications when posts are commented on
    - Create notifications when posts are retweeted

  2. Triggers
    - Set up triggers on likes, comments, and retweets tables
*/

-- Function to create like notifications
CREATE OR REPLACE FUNCTION create_like_notification()
RETURNS TRIGGER AS $$
BEGIN
  -- Only create notification if someone else liked the post
  IF NEW.user_id != (SELECT user_id FROM posts WHERE id = NEW.post_id) THEN
    INSERT INTO notifications (
      user_id,
      type,
      title,
      message,
      post_id
    )
    SELECT 
      p.user_id,
      'like',
      'New Like',
      (SELECT username FROM user_profiles WHERE user_id = NEW.user_id) || ' liked your post',
      NEW.post_id
    FROM posts p
    WHERE p.id = NEW.post_id;
  END IF;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function to create comment notifications
CREATE OR REPLACE FUNCTION create_comment_notification()
RETURNS TRIGGER AS $$
BEGIN
  -- Only create notification if someone else commented on the post
  IF NEW.user_id != (SELECT user_id FROM posts WHERE id = NEW.post_id) THEN
    INSERT INTO notifications (
      user_id,
      type,
      title,
      message,
      post_id
    )
    SELECT 
      p.user_id,
      'comment',
      'New Comment',
      NEW.username || ' commented on your post',
      NEW.post_id
    FROM posts p
    WHERE p.id = NEW.post_id;
  END IF;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function to create retweet notifications
CREATE OR REPLACE FUNCTION create_retweet_notification()
RETURNS TRIGGER AS $$
BEGIN
  -- Only create notification if someone else retweeted the post
  IF NEW.user_id != (SELECT user_id FROM posts WHERE id = NEW.post_id) THEN
    INSERT INTO notifications (
      user_id,
      type,
      title,
      message,
      post_id
    )
    SELECT 
      p.user_id,
      'retweet',
      'New Retweet',
      (SELECT username FROM user_profiles WHERE user_id = NEW.user_id) || ' retweeted your post',
      NEW.post_id
    FROM posts p
    WHERE p.id = NEW.post_id;
  END IF;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers
DROP TRIGGER IF EXISTS trigger_like_notification ON likes;
CREATE TRIGGER trigger_like_notification
  AFTER INSERT ON likes
  FOR EACH ROW
  EXECUTE FUNCTION create_like_notification();

DROP TRIGGER IF EXISTS trigger_comment_notification ON comments;
CREATE TRIGGER trigger_comment_notification
  AFTER INSERT ON comments
  FOR EACH ROW
  EXECUTE FUNCTION create_comment_notification();

DROP TRIGGER IF EXISTS trigger_retweet_notification ON retweets;
CREATE TRIGGER trigger_retweet_notification
  AFTER INSERT ON retweets
  FOR EACH ROW
  EXECUTE FUNCTION create_retweet_notification();