#Sql Injection Prevention

###What is Sql Injection?
SQL injection is a technique used to take advantage of non-validated input vulnerabilities to pass SQL commands through a Web application for execution by a backend database. The result is that the attacker can execute arbitrary SQL queries and/or commands on the backend database server through the Web application.

###Sql Injection in Android
Just like web applications, Android applications may use untrusted input to construct SQL queries and do so in a way that's exploitable. The most common case is when applications do not sanitize input for any SQL and do not limit access to [content providers](http://developer.android.com/intl/ja/guide/topics/providers/content-provider-basics.html#Basics).

Let's take a situation of trying to authorize users by comparing a username supplied by querying a database for it.

```java
public boolean isValidUser(){ 
u_username = EditText( some user value );
u_password = EditText( some user value );
//some un-important code here...
String query = "select * from users_table where username = '" +  u_username + "' and password = '" + u_password +"'";
SQLiteDatabase db
//some un-important code here...
Cursor c = db.rawQuery( p_query, null );
return c.getCount() != 0;
}
```
Problem here is when the user supplies a password '' or '1'='1'. The query being passed to the database then looks like the following:

```java
select * from users_table where username = '" + u_username + "' and password = '' or '1'='1'
```
which will always be set to true, which means that all the rows in the database will meet the selection criteria. This then means that all the rows in users_table will be returned and as result, even if a nonvalid password ' or '1'=' is supplied.

Given that not many Android developers would use the rawQuery call unless they need to pull off some really messy SQL queries, I've included another code snippet of a SQL-injection vulnerability that occurs more often in real-world applications. So when auditing Android code for injection vulnerabilities, a good idea would be to look for something that resembles the following:

```java
public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String  sortOrder)
 {
   SQLiteDBHelper sdbh = new StatementDBHelper(this.getContext());
   Cursor cursor;
   try 
   {
	//some code has been omitted  
   	cursor = sdbh.query(projection,selection,selectionArgs,sortOrder);
   } 
   finally 
   {
      sdbh.close();
   }
   return cursor;
}
```

In the previous code, none of the projection, selection, selectionArgs, or sortOrder variables are sourced directly from external applications. If the content provider is exported and grants URI permissions or, as we've seem before, does not require any permissions, it means that attackers will be able to inject arbitrary SQL to augment the way the malicious query is evaluated.

###Attacking SQL-injection vulnerable content providers using [drozer](https://www.mwrinfosecurity.com/products/drozer/)

There two kinds of SQL-injection vulnerabilities: 

- when the select clause of a SQL statement is injectable 
- when the projection is injectable.

```
dz> run app.provider.query [URI] –-selection "1=1" 
dz> run app.provider.query [URI] –-selection "1-1=0"
dz> run app.provider.query [URI] –-selection "0=0"
dz> run app.provider.query [URI] –-selection "(1+random())*10 > 1"
```
The following is an example of using a purposely vulnerable content provider:

```
dz> run app.provider.query content://com.example.vulnerabledatabase.contentprovider/statements –-selection "1=1"
```
It returns the entire table being queried.

##Securing application components
Application components can be secured both by making proper use of the AndroidManifest.xml file and by forcing permission checks at code level.

Some of the measures that we can take to protect generic components, whether they are activities, broadcast receivers, content providers, or services.

###How to do it?

To start off, we need to review your Android application ***AndroidManifest.xml*** file. The ***android:exported*** attribute defines whether a component can be invoked by other applications. If any of your application components do not need to be invoked by other applications or need to be explicitly shielded from interaction with the components on the rest of the Android system—other than components internal to your application—you should add the following attribute to the application component's XML element:

```xml
<[component name] android:exported="false">
</[component name]>
```

Here the `[component name]` would either be an `activity`, `provider`, `service`, or `receiver`.

###How it works?

Enforcing permissions via the AndroidManifest.xml file means different things to each of the application component types. For every application component, the android:permission attribute does the following:

- **Activity** : Limits the application components which are external to our application that can successfully call.
- **Service** : Limits the external application components that can bind  or start the service.
- **Receiver** : Limits the number of external application components that can send broadcasted intents to the receiver.
- **Provider** : Limits access to data that is made accessible via the content provider

When you define an <intent-filter> element on a component, it will automatically be exported unless you explicitly set exported="false".

##Defending against the SQL-injection attack

The best way to make sure adversaries will not be able to inject unsolicited SQL syntax into your queries is to avoid using SQLiteDatabase.rawQuery() instead opting for a parameterized statement. Using a compiled statement, such as SQLiteStatement, offers both binding and escaping of arguments to defend against SQL-injection attacks. Also, there is a performance benefit due to the fact the database does not need to parse the statement for each execution. An alternative to SQLiteStatement is to use the query, insert, update, and delete methods on SQLiteDatabase as they offer parameterized statements via their use of string arrays.

When we describe parameterized statement, we are describing an SQL statement with a question mark where values will be inserted or binded. Here's an example of parameterized SQL insert statement:

```sql
INSERT VALUES INTO [table name] (?,?,?,?,...)
```
Here [table name] would be the name of the relevant table in which values have to be inserted.

###How to do it?

For this example, we are using a simple Data Access Object ( DAO ) pattern, where all of the database operations for RSS items are contained within the RssItemDAO class:

- When we instantiate RssItemDAO, we compile the insertStatement object with a parameterized SQL insert statement string. This needs to be done only once and can be re-used for multiple inserts:

```java
public class RssItemDAO 
{
	private SQLiteDatabase db;
	private SQLiteStatement insertStatement;
	private static String COL_TITLE = "title";
	private static String TABLE_NAME = "RSS_ITEMS";  
	private static String INSERT_SQL = "insert into  " + TABLE_NAME + " (content, link, title) values (?,?,?)";
	public RssItemDAO(SQLiteDatabase db)
	{
  		this.db = db;
  		insertStatement = db.compileStatement(INSERT_SQL);
  	}	
}
```
The order of the columns noted in the INSERT_SQL variable is important, as it directly maps to the index when binding values. In the preceding example, content maps to index 0, link maps to index 1, and title to index 2.<br>

- Now, when we come to insert a new RssItem object to the database, we bind each of the properties in the order they appear in the statement:

```
public long save(RssItem item) 
{
  insertStatement.bindString(1, item.getContent());
  insertStatement.bindString(2, item.getLink());
  insertStatement.bindString(3, item.getTitle());
  return insertStatement.executeInsert();
}
```
Notice that we call executeInsert, a helper method that returns the ID of the newly created row. It's as simple as that to use a SQLiteStatement statement.

- This shows how to use SQLiteDatabase.query to fetch RssItems that match a given search term:

```java
public List<RssItem> fetchRssItemsByTitle(String searchTerm)
{
	Cursor cursor = db.query(TABLE_NAME, null, COL_TITLE + "LIKE ?",new String[] { "%" + searchTerm + "%" }, null, null, null);
  // process cursor into list
  List<RssItem> rssItems = new ArrayList<RssItemDAO.RssItem>();
  cursor.moveToFirst();
  while (!cursor.isAfterLast()) 
  {
    // maps cursor columns of RssItem properties
    RssItem item = cursorToRssItem(cursor);
    rssItems.add(item);
    cursor.moveToNext();
  }
  return rssItems;
}
```

We use LIKE and the SQL wildcard syntax to match any part of the text with a title column.

###Some quick tips for preventing SQL Injection:

- Implement strong server side validation
- Use parameterized queries
- Avoid rawQuery
- Filter characters in user input ( Eg: "'", "/", ";", "#")
