import { useState } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { Heart, MessageCircle, Repeat2, Share, MoreHorizontal, Info, Flag, UserPlus, UserMinus, Copy, ExternalLink } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { useAuth } from '@/hooks/useAuth';
import { supabase } from '@/integrations/supabase/client';
import { toast } from '@/hooks/use-toast';
import { followsService } from '@/lib/follows';

interface Comment {
  id: string;
  user_id: string;
  username: string;
  user_avatar?: string;
  content: string;
  like_count: number;
  created_at: string;
  parent_id?: string;
  replies?: Comment[];
}

interface Post {
  id: string;
  user_id: string;
  username: string;
  user_avatar?: string;
  content: string;
  post_type: string;
  media_url?: string;
  link_url?: string;
  link_title?: string;
  anime_id?: string;
  anime_title?: string;
  anime_image?: string;
  like_count: number;
  retweet_count: number;
  comment_count: number;
  created_at: string;
  original_post_id?: string;
  isLiked?: boolean;
  isRetweeted?: boolean;
}

interface PostCardProps {
  post: Post;
  onUpdate?: () => void;
}

export const PostCard = ({ post, onUpdate }: PostCardProps) => {
  const { user } = useAuth();
  const [isLiked, setIsLiked] = useState(post.isLiked || false);
  const [isRetweeted, setIsRetweeted] = useState(post.isRetweeted || false);
  const [isFollowing, setIsFollowing] = useState(false);
  const [likeCount, setLikeCount] = useState(post.like_count);
  const [retweetCount, setRetweetCount] = useState(post.retweet_count);
  const [commentCount, setCommentCount] = useState(post.comment_count);
  const [showAnimeInfo, setShowAnimeInfo] = useState(false);
  const [showComments, setShowComments] = useState(false);
  const [showShareDialog, setShowShareDialog] = useState(false);
  const [comments, setComments] = useState<Comment[]>([]);
  const [newComment, setNewComment] = useState('');
  const [replyingTo, setReplyingTo] = useState<string | null>(null);
  const [replyContent, setReplyContent] = useState('');
  const [isSubmittingComment, setIsSubmittingComment] = useState(false);
  const [showReportDialog, setShowReportDialog] = useState(false);
  const [reportReason, setReportReason] = useState('');

  // Check if user is following the post author
  useState(() => {
    if (user && user.id !== post.user_id) {
      followsService.isFollowing(user.id, post.user_id).then(setIsFollowing);
    }
  });

  const handleLike = async () => {
    if (!user) {
      toast({ title: "Error", description: "Please sign in to like posts", variant: "destructive" });
      return;
    }

    try {
      if (isLiked) {
        const { error } = await supabase
          .from('likes')
          .delete()
          .eq('user_id', user.id)
          .eq('post_id', post.id);

        if (error) throw error;
        setIsLiked(false);
        setLikeCount(prev => prev - 1);
      } else {
        const { error } = await supabase
          .from('likes')
          .insert({
            user_id: user.id,
            post_id: post.id
          });

        if (error) throw error;
        setIsLiked(true);
        setLikeCount(prev => prev + 1);
      }
      onUpdate?.();
    } catch (error) {
      toast({ title: "Error", description: "Failed to update like", variant: "destructive" });
    }
  };

  const handleRetweet = async () => {
    if (!user) {
      toast({ title: "Error", description: "Please sign in to retweet posts", variant: "destructive" });
      return;
    }

    try {
      if (isRetweeted) {
        const { error } = await supabase
          .from('retweets')
          .delete()
          .eq('user_id', user.id)
          .eq('post_id', post.id);

        if (error) throw error;
        setIsRetweeted(false);
        setRetweetCount(prev => prev - 1);
      } else {
        const { error } = await supabase
          .from('retweets')
          .insert({
            user_id: user.id,
            post_id: post.id
          });

        if (error) throw error;
        setIsRetweeted(true);
        setRetweetCount(prev => prev + 1);
      }
      onUpdate?.();
    } catch (error) {
      toast({ title: "Error", description: "Failed to update retweet", variant: "destructive" });
    }
  };

  const handleFollow = async () => {
    if (!user || user.id === post.user_id) return;

    try {
      if (isFollowing) {
        await followsService.unfollowUser(user.id, post.user_id);
        setIsFollowing(false);
        toast({ title: "Success", description: `Unfollowed ${post.username}` });
      } else {
        await followsService.followUser(user.id, post.user_id);
        setIsFollowing(true);
        toast({ title: "Success", description: `Now following ${post.username}` });
      }
    } catch (error) {
      toast({ title: "Error", description: "Failed to update follow status", variant: "destructive" });
    }
  };

  const loadComments = async () => {
    try {
      const { data, error } = await supabase
        .from('comments')
        .select('*')
        .eq('post_id', post.id)
        .order('created_at', { ascending: false });

      if (error) throw error;
      
      // Group comments by parent_id to create threaded structure
      const commentsMap = new Map<string, Comment>();
      const rootComments: Comment[] = [];
      
      (data || []).forEach(comment => {
        const commentWithReplies = { ...comment, replies: [] };
        commentsMap.set(comment.id, commentWithReplies);
        
        if (!comment.parent_id) {
          rootComments.push(commentWithReplies);
        }
      });
      
      // Add replies to their parent comments
      (data || []).forEach(comment => {
        if (comment.parent_id && commentsMap.has(comment.parent_id)) {
          const parentComment = commentsMap.get(comment.parent_id)!;
          const childComment = commentsMap.get(comment.id)!;
          parentComment.replies!.push(childComment);
        }
      });
      
      setComments(rootComments);
    } catch (error) {
      console.error('Error loading comments:', error);
    }
  };

  const handleShowComments = () => {
    setShowComments(true);
    loadComments();
  };

  const handleSubmitComment = async () => {
    if (!user || !newComment.trim()) return;

    setIsSubmittingComment(true);
    try {
      const { error } = await supabase
        .from('comments')
        .insert({
          post_id: post.id,
          user_id: user.id,
          username: user.profile?.username || 'Anonymous',
          user_avatar: user.profile?.avatar_url || '',
          content: newComment.trim()
        });

      if (error) throw error;

      setNewComment('');
      setCommentCount(prev => prev + 1);
      loadComments();
      onUpdate?.();
      toast({ title: "Success", description: "Comment posted!" });
    } catch (error) {
      toast({ title: "Error", description: "Failed to post comment", variant: "destructive" });
    } finally {
      setIsSubmittingComment(false);
    }
  };

  const handleSubmitReply = async (parentId: string) => {
    if (!user || !replyContent.trim()) return;

    setIsSubmittingComment(true);
    try {
      const { error } = await supabase
        .from('comments')
        .insert({
          post_id: post.id,
          parent_id: parentId,
          user_id: user.id,
          username: user.profile?.username || 'Anonymous',
          user_avatar: user.profile?.avatar_url || '',
          content: replyContent.trim()
        });

      if (error) throw error;

      setReplyContent('');
      setReplyingTo(null);
      setCommentCount(prev => prev + 1);
      loadComments();
      onUpdate?.();
      toast({ title: "Success", description: "Reply posted!" });
    } catch (error) {
      toast({ title: "Error", description: "Failed to post reply", variant: "destructive" });
    } finally {
      setIsSubmittingComment(false);
    }
  };

  const handleReport = async () => {
    if (!user || !reportReason.trim()) {
      toast({ title: "Error", description: "Please provide a reason for reporting", variant: "destructive" });
      return;
    }

    try {
      const { error } = await supabase
        .from('community_reports')
        .insert({
          reporter_user_id: user.id,
          post_id: post.id,
          reason: reportReason.trim()
        });

      if (error) throw error;

      setShowReportDialog(false);
      setReportReason('');
      toast({ title: "Success", description: "Report submitted. Thank you for helping keep our community safe." });
    } catch (error) {
      toast({ title: "Error", description: "Failed to submit report", variant: "destructive" });
    }
  };

  const handleShare = (platform?: string) => {
    const postUrl = `${window.location.origin}/post/${post.id}`;
    const shareText = `Check out this post by ${post.username}: ${post.content.substring(0, 100)}...`;

    if (platform === 'copy') {
      navigator.clipboard.writeText(postUrl);
      toast({ title: "Success", description: "Link copied to clipboard!" });
    } else if (platform === 'whatsapp') {
      window.open(`https://wa.me/?text=${encodeURIComponent(shareText + ' ' + postUrl)}`, '_blank');
    } else if (platform === 'facebook') {
      window.open(`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(postUrl)}`, '_blank');
    } else if (platform === 'twitter') {
      window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(shareText)}&url=${encodeURIComponent(postUrl)}`, '_blank');
    } else if (navigator.share) {
      navigator.share({
        title: `Post by ${post.username}`,
        text: shareText,
        url: postUrl
      });
    } else {
      navigator.clipboard.writeText(postUrl);
      toast({ title: "Success", description: "Link copied to clipboard!" });
    }
  };

  const extractYouTubeId = (url: string) => {
    const match = url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/)([^&\n?#]+)/);
    return match ? match[1] : null;
  };

  const isYouTubeLink = post.link_url && post.link_url.includes('youtube');
  const youtubeId = isYouTubeLink ? extractYouTubeId(post.link_url!) : null;

  const CommentComponent = ({ comment, isReply = false }: { comment: Comment; isReply?: boolean }) => (
    <div className={`${isReply ? 'ml-8 border-l-2 border-border pl-4' : ''}`}>
      <div className="flex space-x-3 mb-3">
        <Avatar className="h-8 w-8">
          <AvatarImage src={comment.user_avatar} />
          <AvatarFallback className="bg-primary text-primary-foreground text-sm">
            {comment.username[0]?.toUpperCase()}
          </AvatarFallback>
        </Avatar>
        <div className="flex-1">
          <div className="flex items-center space-x-2 mb-1">
            <span className="font-medium text-sm">{comment.username}</span>
            <span className="text-muted-foreground text-xs">
              {formatDistanceToNow(new Date(comment.created_at), { addSuffix: true })}
            </span>
          </div>
          <p className="text-sm mb-2">{comment.content}</p>
          <div className="flex items-center space-x-2">
            <Button variant="ghost" size="sm" className="text-xs h-6 px-2">
              <Heart className="h-3 w-3 mr-1" />
              {comment.like_count}
            </Button>
            {!isReply && (
              <Button 
                variant="ghost" 
                size="sm" 
                className="text-xs h-6 px-2"
                onClick={() => setReplyingTo(replyingTo === comment.id ? null : comment.id)}
              >
                Reply
              </Button>
            )}
          </div>
          
          {/* Reply input */}
          {replyingTo === comment.id && (
            <div className="mt-2 space-y-2">
              <Textarea
                placeholder="Write a reply..."
                value={replyContent}
                onChange={(e) => setReplyContent(e.target.value)}
                className="min-h-[60px] text-sm"
              />
              <div className="flex justify-end space-x-2">
                <Button variant="outline" size="sm" onClick={() => setReplyingTo(null)}>
                  Cancel
                </Button>
                <Button 
                  size="sm"
                  onClick={() => handleSubmitReply(comment.id)}
                  disabled={!replyContent.trim() || isSubmittingComment}
                >
                  {isSubmittingComment ? 'Posting...' : 'Reply'}
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>
      
      {/* Render replies */}
      {comment.replies && comment.replies.length > 0 && (
        <div className="space-y-3">
          {comment.replies.map((reply) => (
            <CommentComponent key={reply.id} comment={reply} isReply={true} />
          ))}
        </div>
      )}
    </div>
  );

  return (
    <Card className="p-4 border-border bg-card hover:bg-accent/5 transition-colors">
      <div className="flex space-x-3">
        <Avatar className="h-12 w-12">
          <AvatarImage src={post.user_avatar} />
          <AvatarFallback className="bg-primary text-primary-foreground">
            {post.username[0]?.toUpperCase()}
          </AvatarFallback>
        </Avatar>

        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-2">
              <span className="font-semibold text-foreground">{post.username}</span>
              <span className="text-muted-foreground text-sm">
                {formatDistanceToNow(new Date(post.created_at), { addSuffix: true })}
              </span>
              {post.anime_title && (
                <Badge 
                  variant="secondary" 
                  className="bg-gradient-to-r from-purple-500/20 to-pink-500/20 text-purple-300 border-purple-500/30 cursor-pointer"
                  onClick={() => setShowAnimeInfo(!showAnimeInfo)}
                >
                  {post.anime_title}
                  <Info className="ml-1 h-3 w-3" />
                </Badge>
              )}
              {/* Follow button */}
              {user && user.id !== post.user_id && (
                <Button
                  variant={isFollowing ? "outline" : "default"}
                  size="sm"
                  onClick={handleFollow}
                  className="h-6 px-2 text-xs"
                >
                  {isFollowing ? (
                    <>
                      <UserMinus className="h-3 w-3 mr-1" />
                      Unfollow
                    </>
                  ) : (
                    <>
                      <UserPlus className="h-3 w-3 mr-1" />
                      Follow
                    </>
                  )}
                </Button>
              )}
            </div>
            
            {user && user.id !== post.user_id && (
              <Dialog open={showReportDialog} onOpenChange={setShowReportDialog}>
                <DialogTrigger asChild>
                  <Button variant="ghost" size="sm" className="text-muted-foreground hover:text-foreground">
                    <MoreHorizontal className="h-4 w-4" />
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Report Post</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4">
                    <Textarea
                      placeholder="Please describe why you're reporting this post..."
                      value={reportReason}
                      onChange={(e) => setReportReason(e.target.value)}
                      className="min-h-[100px]"
                    />
                    <div className="flex justify-end space-x-2">
                      <Button variant="outline" onClick={() => setShowReportDialog(false)}>
                        Cancel
                      </Button>
                      <Button onClick={handleReport} variant="destructive">
                        <Flag className="mr-2 h-4 w-4" />
                        Submit Report
                      </Button>
                    </div>
                  </div>
                </DialogContent>
              </Dialog>
            )}
          </div>

          {/* Anime info */}
          {showAnimeInfo && post.anime_image && (
            <div className="mb-3 p-3 rounded-lg bg-muted/50 border border-purple-500/20">
              <div className="flex space-x-3">
                <img 
                  src={post.anime_image} 
                  alt={post.anime_title}
                  className="w-16 h-20 object-cover rounded"
                />
                <div>
                  <h4 className="font-semibold text-purple-300">{post.anime_title}</h4>
                  <p className="text-sm text-muted-foreground">Related anime</p>
                </div>
              </div>
            </div>
          )}

          <div className="mb-3">
            <p className="text-foreground whitespace-pre-wrap">{post.content}</p>
          </div>

          {/* Media content */}
          {post.media_url && (
            <div className="mb-3 rounded-lg overflow-hidden">
              {post.post_type === 'image' || post.post_type === 'gif' ? (
                <img 
                  src={post.media_url} 
                  alt="Post media"
                  className="w-full max-h-96 object-cover"
                />
              ) : null}
            </div>
          )}

          {/* Link content */}
          {post.link_url && (
            <div className="mb-3">
              {youtubeId ? (
                <div className="rounded-lg overflow-hidden">
                  <iframe
                    width="100%"
                    height="315"
                    src={`https://www.youtube.com/embed/${youtubeId}`}
                    title="YouTube video"
                    frameBorder="0"
                    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                    allowFullScreen
                    className="w-full"
                  />
                </div>
              ) : (
                <a 
                  href={post.link_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block p-3 border border-border rounded-lg hover:bg-accent/50 transition-colors"
                >
                  <div className="text-primary hover:underline">
                    {post.link_title || post.link_url}
                  </div>
                  <div className="text-sm text-muted-foreground truncate">
                    {post.link_url}
                  </div>
                </a>
              )}
            </div>
          )}

          {/* Action buttons */}
          <div className="flex items-center justify-between max-w-md">
            <Button
              variant="ghost"
              size="sm"
              onClick={handleLike}
              className={`flex items-center space-x-2 hover:bg-red-500/10 hover:text-red-500 ${
                isLiked ? 'text-red-500' : 'text-muted-foreground'
              }`}
            >
              <Heart className={`h-4 w-4 ${isLiked ? 'fill-current' : ''}`} />
              <span>{likeCount}</span>
            </Button>

            <Dialog open={showComments} onOpenChange={setShowComments}>
              <DialogTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleShowComments}
                  className="flex items-center space-x-2 hover:bg-blue-500/10 hover:text-blue-500 text-muted-foreground"
                >
                  <MessageCircle className="h-4 w-4" />
                  <span>{commentCount}</span>
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>Comments</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  {/* Add comment */}
                  {user && (
                    <div className="flex space-x-3 border-b border-border pb-4">
                      <Avatar className="h-8 w-8">
                        <AvatarImage src={user.profile?.avatar_url} />
                        <AvatarFallback className="bg-primary text-primary-foreground text-sm">
                          {user.profile?.username?.[0]?.toUpperCase() || 'U'}
                        </AvatarFallback>
                      </Avatar>
                      <div className="flex-1">
                        <Textarea
                          placeholder="Write a comment..."
                          value={newComment}
                          onChange={(e) => setNewComment(e.target.value)}
                          className="min-h-[80px] resize-none"
                        />
                        <div className="flex justify-end mt-2">
                          <Button 
                            onClick={handleSubmitComment}
                            disabled={!newComment.trim() || isSubmittingComment}
                            size="sm"
                          >
                            {isSubmittingComment ? 'Posting...' : 'Comment'}
                          </Button>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Comments list */}
                  <div className="space-y-4">
                    {comments.length === 0 ? (
                      <p className="text-muted-foreground text-center py-4">No comments yet.</p>
                    ) : (
                      comments.map((comment) => (
                        <CommentComponent key={comment.id} comment={comment} />
                      ))
                    )}
                  </div>
                </div>
              </DialogContent>
            </Dialog>

            <Button
              variant="ghost"
              size="sm"
              onClick={handleRetweet}
              className={`flex items-center space-x-2 hover:bg-green-500/10 hover:text-green-500 ${
                isRetweeted ? 'text-green-500' : 'text-muted-foreground'
              }`}
            >
              <Repeat2 className="h-4 w-4" />
              <span>{retweetCount}</span>
            </Button>

            {/* Enhanced Share Dialog */}
            <Dialog open={showShareDialog} onOpenChange={setShowShareDialog}>
              <DialogTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="hover:bg-blue-500/10 hover:text-blue-500 text-muted-foreground"
                >
                  <Share className="h-4 w-4" />
                </Button>
              </DialogTrigger>
              <DialogContent className="sm:max-w-md">
                <DialogHeader>
                  <DialogTitle>Share Post</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div className="flex items-center space-x-2 p-2 border border-border rounded-lg">
                    <Input 
                      value={`${window.location.origin}/post/${post.id}`}
                      readOnly
                      className="flex-1"
                    />
                    <Button 
                      variant="outline" 
                      size="sm"
                      onClick={() => handleShare('copy')}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-2">
                    <Button 
                      variant="outline" 
                      onClick={() => handleShare('whatsapp')}
                      className="flex items-center space-x-2"
                    >
                      <ExternalLink className="h-4 w-4" />
                      <span>WhatsApp</span>
                    </Button>
                    
                    <Button 
                      variant="outline" 
                      onClick={() => handleShare('facebook')}
                      className="flex items-center space-x-2"
                    >
                      <ExternalLink className="h-4 w-4" />
                      <span>Facebook</span>
                    </Button>
                    
                    <Button 
                      variant="outline" 
                      onClick={() => handleShare('twitter')}
                      className="flex items-center space-x-2"
                    >
                      <ExternalLink className="h-4 w-4" />
                      <span>Twitter</span>
                    </Button>
                    
                    <Button 
                      variant="outline" 
                      onClick={() => handleShare()}
                      className="flex items-center space-x-2"
                    >
                      <Share className="h-4 w-4" />
                      <span>More</span>
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </div>
      </div>
    </Card>
  );
};