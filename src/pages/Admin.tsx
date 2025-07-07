import { useEffect, useState } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { supabase } from '@/integrations/supabase/client';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Check, X, RotateCcw, ArrowLeft, Loader2 } from 'lucide-react';
import { toast } from '@/hooks/use-toast';
import { formatDistanceToNow } from 'date-fns';
import { Link, useNavigate } from 'react-router-dom';

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
  status: 'pending' | 'approved' | 'rejected';
  created_at: string;
}

const Admin = () => {
  const { user, isAdmin, loading } = useAuth();
  const [posts, setPosts] = useState<Post[]>([]);
  const [activeTab, setActiveTab] = useState('pending');
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    if (!loading && (!user || !isAdmin)) {
      navigate('/');
    }
  }, [user, isAdmin, loading, navigate]);

  useEffect(() => {
    if (user && isAdmin) {
      fetchPosts();
      setupRealtimeSubscription();
    }
  }, [user, isAdmin]);

  const fetchPosts = async () => {
    if (!user) return;
    
    setIsLoading(true);
    try {
      // Set user context for RLS
      await supabase.rpc('set_user_context', { user_id_param: user.id });

      const { data, error } = await supabase
        .from('posts')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;
      setPosts(data || []);
    } catch (error) {
      console.error('Error fetching posts:', error);
      toast({ title: "Error", description: "Failed to load posts", variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  const setupRealtimeSubscription = () => {
    const channel = supabase
      .channel('admin-posts-changes')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'posts' },
        () => {
          fetchPosts();
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  };

  const updatePostStatus = async (postId: string, status: 'approved' | 'rejected') => {
    try {
      // Set user context for RLS
      await supabase.rpc('set_user_context', { user_id_param: user?.id || '' });

      const { error } = await supabase
        .from('posts')
        .update({ status })
        .eq('id', postId);

      if (error) throw error;

      toast({ 
        title: "Success", 
        description: `Post ${status} successfully` 
      });
      
      fetchPosts();
    } catch (error) {
      console.error('Error updating post status:', error);
      toast({ title: "Error", description: "Failed to update post status", variant: "destructive" });
    }
  };

  const deletePost = async (postId: string) => {
    try {
      // Set user context for RLS
      await supabase.rpc('set_user_context', { user_id_param: user?.id || '' });

      const { error } = await supabase
        .from('posts')
        .delete()
        .eq('id', postId);

      if (error) throw error;

      toast({ title: "Success", description: "Post deleted successfully" });
      fetchPosts();
    } catch (error) {
      console.error('Error deleting post:', error);
      toast({ title: "Error", description: "Failed to delete post", variant: "destructive" });
    }
  };

  const filterPostsByStatus = (status: string) => {
    return posts.filter(post => post.status === status);
  };

  const PostCard = ({ post }: { post: Post }) => (
    <Card className="p-4 border-border bg-card">
      <div className="flex space-x-3">
        <Avatar className="h-12 w-12">
          <AvatarImage src={post.user_avatar} />
          <AvatarFallback className="bg-primary text-primary-foreground">
            {post.username[0]?.toUpperCase()}
          </AvatarFallback>
        </Avatar>

        <div className="flex-1">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-2">
              <span className="font-semibold">{post.username}</span>
              <span className="text-muted-foreground text-sm">
                {formatDistanceToNow(new Date(post.created_at), { addSuffix: true })}
              </span>
              <Badge 
                variant={post.status === 'approved' ? 'default' : post.status === 'rejected' ? 'destructive' : 'secondary'}
              >
                {post.status}
              </Badge>
              {post.anime_title && (
                <Badge variant="outline" className="text-purple-400 border-purple-400/50">
                  {post.anime_title}
                </Badge>
              )}
            </div>
          </div>

          <div className="mb-3">
            <p className="text-foreground whitespace-pre-wrap">{post.content}</p>
          </div>

          {/* Media preview */}
          {post.media_url && (
            <div className="mb-3">
              <img 
                src={post.media_url} 
                alt="Post media"
                className="max-h-64 rounded-lg object-cover"
              />
            </div>
          )}

          {/* Link preview */}
          {post.link_url && (
            <div className="mb-3 p-2 border border-border rounded">
              <p className="text-primary text-sm">{post.link_title || 'Link'}</p>
              <p className="text-muted-foreground text-xs truncate">{post.link_url}</p>
            </div>
          )}

          {/* Anime info */}
          {post.anime_image && (
            <div className="mb-3 flex items-center space-x-2">
              <img 
                src={post.anime_image} 
                alt={post.anime_title}
                className="w-12 h-16 object-cover rounded"
              />
              <div>
                <p className="text-sm font-medium text-purple-400">{post.anime_title}</p>
                <p className="text-xs text-muted-foreground">Tagged anime</p>
              </div>
            </div>
          )}

          {/* Action buttons */}
          <div className="flex items-center space-x-2">
            {post.status === 'pending' && (
              <>
                <Button
                  size="sm"
                  onClick={() => updatePostStatus(post.id, 'approved')}
                  className="bg-green-600 hover:bg-green-700"
                >
                  <Check className="mr-1 h-4 w-4" />
                  Approve
                </Button>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => updatePostStatus(post.id, 'rejected')}
                >
                  <X className="mr-1 h-4 w-4" />
                  Reject
                </Button>
              </>
            )}
            
            {post.status === 'approved' && (
              <Button
                size="sm"
                variant="destructive"
                onClick={() => updatePostStatus(post.id, 'rejected')}
              >
                <X className="mr-1 h-4 w-4" />
                Reject
              </Button>
            )}
            
            {post.status === 'rejected' && (
              <Button
                size="sm"
                onClick={() => updatePostStatus(post.id, 'approved')}
                className="bg-green-600 hover:bg-green-700"
              >
                <RotateCcw className="mr-1 h-4 w-4" />
                Restore
              </Button>
            )}
            
            <Button
              size="sm"
              variant="outline"
              onClick={() => deletePost(post.id)}
              className="text-destructive border-destructive hover:bg-destructive/10"
            >
              Delete
            </Button>
          </div>
        </div>
      </div>
    </Card>
  );

  if (loading || isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-12 w-12 animate-spin mx-auto mb-4" />
          <p className="text-muted-foreground">Loading admin panel...</p>
        </div>
      </div>
    );
  }

  if (!user || !isAdmin) return null;

  const pendingPosts = filterPostsByStatus('pending');
  const approvedPosts = filterPostsByStatus('approved');
  const rejectedPosts = filterPostsByStatus('rejected');

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Button variant="ghost" size="sm" asChild>
              <Link to="/">
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to Feed
              </Link>
            </Button>
            <h1 className="text-2xl font-bold">Admin Panel</h1>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-6xl mx-auto px-4 py-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-3 mb-6">
            <TabsTrigger value="pending" className="relative">
              Pending 
              {pendingPosts.length > 0 && (
                <Badge variant="destructive" className="ml-2 h-5 w-5 p-0 text-xs">
                  {pendingPosts.length}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="approved">Approved ({approvedPosts.length})</TabsTrigger>
            <TabsTrigger value="rejected">Rejected ({rejectedPosts.length})</TabsTrigger>
          </TabsList>

          <TabsContent value="pending" className="space-y-4">
            {pendingPosts.length === 0 ? (
              <div className="text-center py-12">
                <p className="text-muted-foreground">No pending posts to review.</p>
              </div>
            ) : (
              pendingPosts.map((post) => (
                <PostCard key={post.id} post={post} />
              ))
            )}
          </TabsContent>

          <TabsContent value="approved" className="space-y-4">
            {approvedPosts.length === 0 ? (
              <div className="text-center py-12">
                <p className="text-muted-foreground">No approved posts.</p>
              </div>
            ) : (
              approvedPosts.map((post) => (
                <PostCard key={post.id} post={post} />
              ))
            )}
          </TabsContent>

          <TabsContent value="rejected" className="space-y-4">
            {rejectedPosts.length === 0 ? (
              <div className="text-center py-12">
                <p className="text-muted-foreground">No rejected posts.</p>
              </div>
            ) : (
              rejectedPosts.map((post) => (
                <PostCard key={post.id} post={post} />
              ))
            )}
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default Admin;