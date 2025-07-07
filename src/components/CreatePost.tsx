import { useState, useRef } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Image, Link2, Search, X, Loader2, Smile } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { supabase } from '@/integrations/supabase/client';
import { animeService, Anime } from '@/lib/anime';
import { toast } from '@/hooks/use-toast';

interface CreatePostProps {
  onPostCreated?: () => void;
}

export const CreatePost = ({ onPostCreated }: CreatePostProps) => {
  const { user } = useAuth();
  const [content, setContent] = useState('');
  const [mediaFile, setMediaFile] = useState<File | null>(null);
  const [mediaPreview, setMediaPreview] = useState<string | null>(null);
  const [linkUrl, setLinkUrl] = useState('');
  const [linkTitle, setLinkTitle] = useState('');
  const [selectedAnime, setSelectedAnime] = useState<Anime | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [animeSearch, setAnimeSearch] = useState('');
  const [animeResults, setAnimeResults] = useState<Anime[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [showAnimeDialog, setShowAnimeDialog] = useState(false);
  const [showLinkDialog, setShowLinkDialog] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const searchAnime = async (query: string) => {
    if (!query.trim()) {
      setAnimeResults([]);
      return;
    }

    setIsSearching(true);
    try {
      const results = await animeService.searchAnime(query, 10);
      setAnimeResults(results);
    } catch (error) {
      console.error('Error searching anime:', error);
    } finally {
      setIsSearching(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Check file size (max 10MB)
    if (file.size > 10 * 1024 * 1024) {
      toast({ title: "Error", description: "File size must be less than 10MB", variant: "destructive" });
      return;
    }

    // Check file type
    if (!file.type.startsWith('image/')) {
      toast({ title: "Error", description: "Only image files are allowed", variant: "destructive" });
      return;
    }

    setMediaFile(file);
    const reader = new FileReader();
    reader.onload = (e) => {
      setMediaPreview(e.target?.result as string);
    };
    reader.readAsDataURL(file);
  };

  const removeMedia = () => {
    setMediaFile(null);
    setMediaPreview(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const removeLink = () => {
    setLinkUrl('');
    setLinkTitle('');
    setShowLinkDialog(false);
  };

  const removeAnime = () => {
    setSelectedAnime(null);
  };

  const uploadMedia = async (file: File, userId: string): Promise<string | null> => {
    try {
      const fileExt = file.name.split('.').pop();
      const fileName = `${Date.now()}.${fileExt}`;
      const filePath = `${userId}/${fileName}`;

      const { error: uploadError } = await supabase.storage
        .from('post-media')
        .upload(filePath, file);

      if (uploadError) throw uploadError;

      const { data: { publicUrl } } = supabase.storage
        .from('post-media')
        .getPublicUrl(filePath);

      return publicUrl;
    } catch (error) {
      console.error('Error uploading media:', error);
      return null;
    }
  };

  const handleSubmit = async () => {
    if (!user) {
      toast({ title: "Error", description: "Please sign in to create posts", variant: "destructive" });
      return;
    }

    if (!content.trim() && !mediaFile && !linkUrl) {
      toast({ title: "Error", description: "Please add some content to your post", variant: "destructive" });
      return;
    }

    setIsSubmitting(true);
    
    try {
      // Set user context FIRST - this is critical for RLS
      console.log('Setting user context for user:', user.id);
      await supabase.rpc('set_user_context', { user_id_param: user.id });
      
      // Small delay to ensure context is set
      await new Promise(resolve => setTimeout(resolve, 100));

      let mediaUrl = null;
      let postType = 'text';

      // Upload media if present
      if (mediaFile) {
        console.log('Uploading media...');
        mediaUrl = await uploadMedia(mediaFile, user.id);
        if (!mediaUrl) {
          throw new Error('Failed to upload media');
        }
        postType = mediaFile.type.startsWith('image/') ? 'image' : 'gif';
      } else if (linkUrl) {
        postType = 'link';
      }

      // Create post data with explicit user context
      const postData = {
        user_id: user.id, // Explicit user ID
        username: user.profile?.username || 'Anonymous',
        user_avatar: user.profile?.avatar_url || '',
        content: content.trim(),
        post_type: postType as 'text' | 'image' | 'gif' | 'link',
        media_url: mediaUrl,
        link_url: linkUrl || null,
        link_title: linkTitle || null,
        anime_id: selectedAnime?.mal_id?.toString() || null,
        anime_title: selectedAnime?.title || null,
        anime_image: selectedAnime?.images?.jpg?.image_url || null,
        status: 'pending' as 'pending',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      console.log('Creating post with data:', postData);

      // Insert the post
      const { data, error } = await supabase
        .from('posts')
        .insert(postData)
        .select()
        .single();

      if (error) {
        console.error('Post creation error:', error);
        throw new Error(error.message || 'Failed to create post');
      }

      console.log('Post created successfully:', data);

      // Reset form
      setContent('');
      setMediaFile(null);
      setMediaPreview(null);
      setLinkUrl('');
      setLinkTitle('');
      setSelectedAnime(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }

      toast({ 
        title: "Success", 
        description: "Post submitted for review! It will appear once approved." 
      });
      
      onPostCreated?.();
    } catch (error: any) {
      console.error('Error creating post:', error);
      toast({ 
        title: "Error", 
        description: error.message || "Failed to create post. Please try again.", 
        variant: "destructive" 
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const addEmoji = (emoji: string) => {
    setContent(prev => prev + emoji);
  };

  const popularEmojis = ['😀', '😂', '😍', '🥰', '😎', '🤔', '😭', '🔥', '💯', '❤️', '👍', '🎉'];

  if (!user) return null;

  return (
    <Card className="p-4 border-border bg-card">
      <div className="flex space-x-3">
        <Avatar className="h-12 w-12">
          <AvatarImage src={user.profile?.avatar_url} />
          <AvatarFallback className="bg-primary text-primary-foreground">
            {user.profile?.username?.[0]?.toUpperCase() || 'U'}
          </AvatarFallback>
        </Avatar>

        <div className="flex-1">
          <Textarea
            placeholder="What's happening in the anime world?"
            value={content}
            onChange={(e) => setContent(e.target.value)}
            className="min-h-[120px] resize-none border-0 bg-transparent text-lg placeholder:text-muted-foreground focus-visible:ring-0"
            maxLength={280}
            disabled={isSubmitting}
          />

          {/* Selected anime */}
          {selectedAnime && (
            <div className="mt-3 p-3 rounded-lg bg-gradient-to-r from-purple-500/10 to-pink-500/10 border border-purple-500/20">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <img 
                    src={selectedAnime.images?.jpg?.small_image_url} 
                    alt={selectedAnime.title}
                    className="w-12 h-16 object-cover rounded"
                  />
                  <div>
                    <p className="font-semibold text-purple-300">{selectedAnime.title}</p>
                    <p className="text-sm text-muted-foreground">Anime tag</p>
                  </div>
                </div>
                <Button variant="ghost" size="sm" onClick={removeAnime} disabled={isSubmitting}>
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}

          {/* Media preview */}
          {mediaPreview && (
            <div className="mt-3 relative">
              <img src={mediaPreview} alt="Preview" className="max-h-64 rounded-lg" />
              <Button
                variant="secondary"
                size="sm"
                className="absolute top-2 right-2"
                onClick={removeMedia}
                disabled={isSubmitting}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
          )}

          {/* Link preview */}
          {linkUrl && (
            <div className="mt-3 p-3 border border-border rounded-lg">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-primary">{linkTitle || 'Link'}</p>
                  <p className="text-sm text-muted-foreground truncate">{linkUrl}</p>
                </div>
                <Button variant="ghost" size="sm" onClick={removeLink} disabled={isSubmitting}>
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}

          <div className="flex items-center justify-between mt-4">
            <div className="flex items-center space-x-2">
              {/* Media upload */}
              <Button
                variant="ghost"
                size="sm"
                onClick={() => fileInputRef.current?.click()}
                className="text-primary hover:bg-primary/10"
                disabled={isSubmitting}
              >
                <Image className="h-5 w-5" />
              </Button>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                onChange={handleFileChange}
                className="hidden"
                disabled={isSubmitting}
              />

              {/* Link input dialog */}
              <Dialog open={showLinkDialog} onOpenChange={setShowLinkDialog}>
                <DialogTrigger asChild>
                  <Button variant="ghost" size="sm" className="text-primary hover:bg-primary/10" disabled={isSubmitting}>
                    <Link2 className="h-5 w-5" />
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Add Link</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4">
                    <div>
                      <Input
                        placeholder="Enter URL"
                        value={linkUrl}
                        onChange={(e) => setLinkUrl(e.target.value)}
                      />
                    </div>
                    <div>
                      <Input
                        placeholder="Link title (optional)"
                        value={linkTitle}
                        onChange={(e) => setLinkTitle(e.target.value)}
                      />
                    </div>
                    <div className="flex justify-end space-x-2">
                      <Button variant="outline" onClick={() => setShowLinkDialog(false)}>
                        Cancel
                      </Button>
                      <Button onClick={() => setShowLinkDialog(false)}>
                        Add Link
                      </Button>
                    </div>
                  </div>
                </DialogContent>
              </Dialog>

              {/* Anime search dialog */}
              <Dialog open={showAnimeDialog} onOpenChange={setShowAnimeDialog}>
                <DialogTrigger asChild>
                  <Button variant="ghost" size="sm" className="text-purple-400 hover:bg-purple-400/10" disabled={isSubmitting}>
                    <Search className="h-5 w-5" />
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-md max-h-[600px]">
                  <DialogHeader>
                    <DialogTitle>Tag Anime</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4">
                    <Input
                      placeholder="Search anime..."
                      value={animeSearch}
                      onChange={(e) => {
                        setAnimeSearch(e.target.value);
                        searchAnime(e.target.value);
                      }}
                    />
                    
                    {isSearching && (
                      <div className="flex justify-center py-4">
                        <Loader2 className="h-6 w-6 animate-spin" />
                      </div>
                    )}

                    <div className="max-h-80 overflow-y-auto space-y-2">
                      {animeResults.map((anime) => (
                        <div
                          key={anime.mal_id}
                          onClick={() => {
                            setSelectedAnime(anime);
                            setShowAnimeDialog(false);
                            setAnimeSearch('');
                            setAnimeResults([]);
                          }}
                          className="flex items-center space-x-3 p-2 rounded-lg hover:bg-accent cursor-pointer"
                        >
                          <img 
                            src={anime.images?.jpg?.small_image_url} 
                            alt={anime.title}
                            className="w-10 h-14 object-cover rounded"
                          />
                          <div className="flex-1 min-w-0">
                            <p className="font-medium truncate">{anime.title}</p>
                            <p className="text-sm text-muted-foreground">
                              {anime.score ? `⭐ ${anime.score}` : 'No rating'}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </DialogContent>
              </Dialog>

              {/* Emoji picker */}
              <Dialog>
                <DialogTrigger asChild>
                  <Button variant="ghost" size="sm" className="text-yellow-400 hover:bg-yellow-400/10" disabled={isSubmitting}>
                    <Smile className="h-5 w-5" />
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-sm">
                  <DialogHeader>
                    <DialogTitle>Add Emoji</DialogTitle>
                  </DialogHeader>
                  <div className="grid grid-cols-6 gap-2">
                    {popularEmojis.map((emoji) => (
                      <Button
                        key={emoji}
                        variant="ghost"
                        size="sm"
                        onClick={() => addEmoji(emoji)}
                        className="text-2xl h-12 w-12"
                      >
                        {emoji}
                      </Button>
                    ))}
                  </div>
                </DialogContent>
              </Dialog>
            </div>

            <div className="flex items-center space-x-3">
              <span className={`text-sm ${content.length > 260 ? 'text-destructive' : 'text-muted-foreground'}`}>
                {280 - content.length}
              </span>
              <Button 
                onClick={handleSubmit}
                disabled={isSubmitting || (!content.trim() && !mediaFile && !linkUrl)}
                className="bg-primary hover:bg-primary/90"
              >
                {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {isSubmitting ? 'Posting...' : 'Post'}
              </Button>
            </div>
          </div>
        </div>
      </div>
    </Card>
  );
};