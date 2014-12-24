using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System;
using System.IO;
using System.Collections.Generic;
namespace GoldPython.Wrapper.Tietuku
{
	public class TietukuWrapper
	{
		public const string ApiUrlUp ="http://up.tietuku.com/";
		
		public string GetToken(Dictionary<string,object> param)
		{
			return TokenUtility.CreateToken(AccessKey,SecretKey,param);
		}
		public void SignParam(Dictionary<string,object> param)
		{
			var token = GetToken(param);
			param.Clear();
			param.Add("Token",token);
		}
		public Dictionary<string,object> GetParamDict(string action)
		{
			var dict = new Dictionary<string,object>();
			dict.Add("deadline",DateTime.Now.ToUnixTimestamp()+60);
			if(!string.IsNullOrWhiteSpace(action))
				dict.Add("action",action);
			return dict;
		}
		public string AccessKey{get;set;}
		public string SecretKey{get;set;}
		public TietukuWrapper(string accesskey,string secretKey)
		{
			this.AccessKey = accesskey;
			this.SecretKey = secretKey;
		}
		public string UpFile(int aid,string filepath)
		{
			var param = GetParamDict(null);
			param.Add("aid",aid);
			param.Add("from","file");
			SignParam(param);
			param.Add("file", new FileInfo(filepath));
			return AjaxUtility.MultipartFormDataPost(ApiUrlUp,param);
		}
		public string UpUrl(int aid,string fileurl)
		{
			var param = GetParamDict(null);
			param.Add("aid",aid);
			param.Add("from","web");
			SignParam(param);
			param.Add("fileurl", fileurl);
			return AjaxUtility.Post(ApiUrlUp,param);
		}
		
		public const string ApiUrlAlbum ="http://api.tietuku.com/v1/Album";
		public string AlbumList(int? uid=null)
		{
			var param = GetParamDict("get");
			if(uid!=null)
				param.Add("uid",uid);
			SignParam(param);
			return AjaxUtility.Post(ApiUrlAlbum,param);
		}
		public string AlbumCreate(string albumname)
		{
			var param = GetParamDict("create");
			param.Add("albumname",albumname);
			SignParam(param);
			return AjaxUtility.Post(ApiUrlAlbum,param);
		}
		public string AlbumEdit(int aid,string albumname)
		{
			var param = GetParamDict("editalbum");
			param.Add("aid",aid);
			param.Add("albumname",albumname);
			SignParam(param);
			return AjaxUtility.Post(ApiUrlAlbum,param);
		}
		public string AlbumDelete(int aid)
		{
			var param = GetParamDict("delalbum");
			param.Add("aid",aid);
			SignParam(param);
			return AjaxUtility.Post(ApiUrlAlbum,param);
		}
		
		public const string ApiUrlList ="http://api.tietuku.com/v1/List";
		public string ListRandomPicture(int cid)
		{
			var param = GetParamDict("getrandrec");
			param.Add("cid",cid);
			SignParam(param);
			return AjaxUtility.Post(ApiUrlAlbum,param);
		}
		public string ListPicture(int cid)
		{
			var param = GetParamDict("getnewpic");
			param.Add("cid",cid);
			param.Add("page_no",1);
			SignParam(param);
			return AjaxUtility.Post(ApiUrlList,param);
		}
		public string ListAlbumPicture(int aid,int page_no)
		{
			var param = GetParamDict("album");
			param.Add("aid",aid);
			param.Add("page_no",1);
			SignParam(param);
			return AjaxUtility.Post(ApiUrlList,param);
		}
		public string ListPicture(string[] ids)
		{
			var param = GetParamDict("getpicbyids");
			param.Add("ids",string.Join(",",ids));
			SignParam(param);
			return AjaxUtility.Post(ApiUrlList,param);
		}
		public const string ApiUrlPic ="http://api.tietuku.com/v1/Pic";
		public string Picture(string id="",string findurl="")
		{
			var param = GetParamDict("getonepic");
			if(!string.IsNullOrWhiteSpace(findurl))
			{
				param.Add("findurl",findurl);
			}
			if(!string.IsNullOrWhiteSpace(id))
			{
				param.Add("id",id);
			}
			SignParam(param);
			return AjaxUtility.Post(ApiUrlList,param);
		}
		
		public const string ApiUrlCollect ="http://api.tietuku.com/v1/Collect";
		public string CollectPicture(string page_no)
		{
			var param = GetParamDict("getlovepic");
			param.Add("page_no",page_no);
			SignParam(param);
			return AjaxUtility.Post(ApiUrlList,param);
		}
		public string CollectAdd(string id)
		{
			var param = GetParamDict("addcollect");
			param.Add("id",id);
			SignParam(param);
			return AjaxUtility.Post(ApiUrlList,param);
		}
		public string CollectDelete(string id)
		{
			var param = GetParamDict("delcollect");
			param.Add("id",id);
			SignParam(param);
			return AjaxUtility.Post(ApiUrlList,param);
		}
		public const string ApiUrlCatalog = "http://api.tietuku.com/v1/Catalog";
		public string Catalog()
		{
			var param = GetParamDict("getall");
			SignParam(param);
			return AjaxUtility.Post(ApiUrlList,param);
		}
	}
	public static class Extensions
	{
		public static int ToUnixTimestamp(this DateTime time)
		{
			System.DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(new System.DateTime(1970, 1, 1));
			return (int)(time - startTime).TotalSeconds;
		}
	}
	public static class AjaxUtility
	{
		public static Encoding DefaultEncoding = Encoding.UTF8;
		public static string Post(string url, IEnumerable<KeyValuePair<string, object>> parameters = null)
		{
			if (string.IsNullOrEmpty(url))
			{
				throw new ArgumentNullException("url");
			}
			var ajaxEncoding = DefaultEncoding;
			HttpWebRequest request = null;
			//如果是发送HTTPS请求
			if (url.StartsWith("https", StringComparison.OrdinalIgnoreCase))
			{
				ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(CheckValidationResult);
				request = WebRequest.Create(url) as HttpWebRequest;
				request.ProtocolVersion = HttpVersion.Version10;
			}
			else
			{
				request = WebRequest.Create(url) as HttpWebRequest;
			}
			request.Method = "POST";
			request.ContentType = "application/x-www-form-urlencoded";
			if (parameters != null && parameters.Count() > 0)
			{
				string buffer = string.Join("&", parameters.Select(i => string.Format("{0}={1}", i.Key, i.Value)));
				byte[] data = ajaxEncoding.GetBytes(buffer.ToString());
				using (Stream stream = request.GetRequestStream())
				{
					stream.Write(data, 0, data.Length);
				}
			}
			using (var response = request.GetResponse())
			{
				using (var stream = response.GetResponseStream())
				{
					using (var reader = new StreamReader(stream, DefaultEncoding))
					{
						return reader.ReadToEnd();
					}
				}
			}
		}
		public static string MultipartFormDataPost(string postUrl, Dictionary<string, object> postParameters,string userAgent=null)
		{
			string formDataBoundary = String.Format("----------{0:N}", Guid.NewGuid());
			string contentType = "multipart/form-data; boundary=" + formDataBoundary;
			byte[] formData = GetMultipartFormData(postParameters, formDataBoundary);
			HttpWebRequest request = WebRequest.Create(postUrl) as HttpWebRequest;
			if (request == null)
			{
				throw new NullReferenceException("request is not a http request");
			}
			
			// Set up the request properties.
			request.Method = "POST";
			request.ContentType = contentType;
			request.UserAgent = userAgent;
			request.CookieContainer = new CookieContainer();
			request.ContentLength = formData.Length;
			
			// You could add authentication here as well if needed:
			// request.PreAuthenticate = true;
			// request.AuthenticationLevel = System.Net.Security.AuthenticationLevel.MutualAuthRequested;
			// request.Headers.Add("Authorization", "Basic " + Convert.ToBase64String(System.Text.Encoding.Default.GetBytes("username" + ":" + "password")));
			
			// Send the form data to the request.
			using (Stream requestStream = request.GetRequestStream())
			{
				requestStream.Write(formData, 0, formData.Length);
				requestStream.Close();
			}
			
			using (var response = request.GetResponse())
			{
				using (var stream = response.GetResponseStream())
				{
					using (var reader = new StreamReader(stream, DefaultEncoding))
					{
						return reader.ReadToEnd();
					}
				}
			}
		}
		private static bool CheckValidationResult(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
		{
			return true; //总是接受
		}
		private static byte[] GetMultipartFormData(Dictionary<string, object> postParameters, string boundary)
		{
			Stream formDataStream = new System.IO.MemoryStream();
			bool needsCLRF = false;
			foreach (var param in postParameters)
			{
				// Thanks to feedback from commenters, add a CRLF to allow multiple parameters to be added.
				// Skip it on the first parameter, add it to subsequent parameters.
				if (needsCLRF)
					formDataStream.Write(DefaultEncoding.GetBytes("\r\n"), 0, DefaultEncoding.GetByteCount("\r\n"));
				needsCLRF = true;
				if (param.Value is FileInfo)
				{
					var fileinfo = (FileInfo)param.Value;
					
					// Add just the first part of this param, since we will write the file data directly to the Stream
					string header = string.Format("--{0}\r\nContent-Disposition: form-data; name=\"{1}\"; filename=\"{2}\"\r\nContent-Type: {3}\r\n\r\n",
					                              boundary,
					                              param.Key,
					                              fileinfo.Name ?? param.Key,
					                              "application/octet-stream");
					formDataStream.Write(DefaultEncoding.GetBytes(header), 0, DefaultEncoding.GetByteCount(header));
					// Write the file data directly to the Stream, rather than serializing it to a string.
					using(var fs = new FileStream(fileinfo.FullName,FileMode.Open))
					{
						var bytes = new byte[fs.Length];
						fs.Read(bytes,0,bytes.Length);
						formDataStream.Write(bytes, 0, bytes.Length);
					}
				}
				else
				{
					string postData = string.Format("--{0}\r\nContent-Disposition: form-data; name=\"{1}\"\r\n\r\n{2}",
					                                boundary,
					                                param.Key,
					                                param.Value);
					formDataStream.Write(DefaultEncoding.GetBytes(postData), 0, DefaultEncoding.GetByteCount(postData));
				}
			}
			
			// Add the end of the request.  Start with a newline
			string footer = "\r\n--" + boundary + "--\r\n";
			formDataStream.Write(DefaultEncoding.GetBytes(footer), 0, DefaultEncoding.GetByteCount(footer));
			
			// Dump the Stream into a byte[]
			formDataStream.Position = 0;
			byte[] formData = new byte[formDataStream.Length];
			formDataStream.Read(formData, 0, formData.Length);
			formDataStream.Close();
			
			return formData;
		}
	}
	public class TokenUtility
	{
		public static string CreateToken(string accesskey,string secretKey,Dictionary<string,object> param)
		{
			var json = string.Format("{{{0}}}",string.Join(",",param.Select(i=>string.Format("\"{0}\":{1}",i.Key,i.Value is string?string.Format("\"{0}\"",i.Value):i.Value))));
			var base64param = Base64Util.Base64(json);
			var sign = HmacUtil.HmacSha1(base64param , secretKey);
			var token = accesskey+":"+sign+":"+base64param;
			return token;
		}
		public class HmacUtil {
			public static String HmacSha1(String value, String key)
			{
				byte[] keyBytes = Encoding.UTF8.GetBytes(key);
				var mac = new System.Security.Cryptography.HMACSHA1(keyBytes);
				byte[] rawHmac = mac.ComputeHash(Encoding.UTF8.GetBytes(value));
				return Base64Util.Base64(rawHmac);
			}
		}
		public class Base64Util {
			public static String Base64(string target)
			{
				var byteArray = Encoding.UTF8.GetBytes(target);
				return Base64(byteArray);
			}
			public static string Base64(byte[] target)
			{
				return Convert.ToBase64String(target).Replace('+', '-').Replace('/', '_');
			}
		}
	}
}

